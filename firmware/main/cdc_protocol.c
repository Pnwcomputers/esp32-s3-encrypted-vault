#include "cdc_protocol.h"
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/ringbuf.h"
#include "esp_log.h"
#include "tinyusb.h"
#include "tinyusb_default_config.h"
#include "tinyusb_cdc_acm.h"
#include "vault_storage.h"
#include "status_led.h"
#include "vault_runtime.h"
#include "vault_msc.h"
#include "esp_timer.h"
#include "freertos/semphr.h"

static const char *TAG = "cdc_protocol";

#define RX_BUFFER_SIZE  16384
#define STACK_SIZE       8192

static RingbufHandle_t s_rx_ringbuf = NULL;
static TaskHandle_t s_protocol_task_hdl = NULL;
static volatile bool s_running = false;
static SemaphoreHandle_t s_stopped;
static cdc_ui_transfer_cb_t s_ui_transfer_cb = NULL;

static uint32_t s_crc32_table[256];
static bool s_crc32_table_inited = false;

static void init_crc32_table(void) {
    if (s_crc32_table_inited) return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) {
            c = (c & 1) ? (0xEDB88320L ^ (c >> 1)) : (c >> 1);
        }
        s_crc32_table[i] = c;
    }
    s_crc32_table_inited = true;
}

static uint32_t compute_crc32(const uint8_t *data, size_t length) {
    if (!s_crc32_table_inited) init_crc32_table();
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++) {
        crc = s_crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

static esp_err_t send_response(uint8_t command, uint32_t request_id, const uint8_t *payload, uint32_t payload_len) {
    protocol_header_t hdr;
    memcpy(hdr.magic, PROTOCOL_MAGIC, 4);
    hdr.version = PROTOCOL_VERSION;
    hdr.command = command;
    hdr.request_id = request_id;
    hdr.payload_len = payload_len;

    size_t total_len = sizeof(hdr) + payload_len + PROTOCOL_CRC_SIZE;
    uint8_t *frame = malloc(total_len);
    if (!frame) {
        ESP_LOGE(TAG, "Cannot allocate response frame (%zu bytes)", total_len);
        return ESP_ERR_NO_MEM;
    }

    memcpy(frame, &hdr, sizeof(hdr));
    if (payload_len > 0 && payload) {
        memcpy(frame + sizeof(hdr), payload, payload_len);
    }

    uint32_t crc = compute_crc32(frame, sizeof(hdr) + payload_len);
    memcpy(frame + sizeof(hdr) + payload_len, &crc, PROTOCOL_CRC_SIZE);

    int64_t deadline = esp_timer_get_time() + 2000000;
    size_t written = 0;
    while (written < total_len) {
        size_t chunk = total_len - written;
        if (chunk > 256) chunk = 256;

        size_t q = tinyusb_cdcacm_write_queue(TINYUSB_CDC_ACM_0, frame + written, chunk);
        tinyusb_cdcacm_write_flush(TINYUSB_CDC_ACM_0, pdMS_TO_TICKS(50));
        if (esp_timer_get_time() > deadline) { free(frame); return ESP_ERR_TIMEOUT; }
        if (q == 0) vTaskDelay(pdMS_TO_TICKS(1));
        written += q;
    }

    free(frame);
    return ESP_OK;
}

static esp_err_t send_status_response(uint8_t command, uint32_t request_id, uint8_t status) {
    return send_response(command, request_id, &status, 1);
}

static void handle_get_status(uint32_t req_id, const uint8_t *payload, uint32_t len) {
    uint32_t total_mb = 0, free_mb = 0, file_count = 0;
    if (vault_storage_is_unlocked()) vault_storage_get_stats(&total_mb, &free_mb, &file_count);

    uint8_t resp[16];
    resp[0] = STATUS_OK;
    resp[1] = vault_storage_is_unlocked() ? 1 : 0;
    uint16_t fw_ver = 0x0101; /* v1.1.x: protocol encodes major/minor only. */
    memcpy(resp + 2, &fw_ver, 2);
    memcpy(resp + 4, &total_mb, 4);
    memcpy(resp + 8, &free_mb, 4);
    memcpy(resp + 12, &file_count, 4);

    send_response(CMD_GET_STATUS, req_id, resp, sizeof(resp));
}

static void handle_list_files(uint32_t req_id, const uint8_t *payload, uint32_t len) {
    if (!vault_storage_is_unlocked()) {
        send_status_response(CMD_LIST_FILES, req_id, STATUS_ERR_LOCKED);
        return;
    }

    size_t count = 0;
    vault_storage_list_files(NULL, 0, &count);

    vault_file_record_t *records = NULL;
    if (count > 0) {
        records = malloc(count * sizeof(vault_file_record_t));
        if (!records) {
            send_status_response(CMD_LIST_FILES, req_id, STATUS_ERR_NO_MEM);
            return;
        }
        vault_storage_list_files(records, count, &count);
    }

    // Allocate buffer for status + count + files
    size_t buf_cap = 1 + 4 + (count * (2 + VAULT_MAX_FILENAME_LEN + 8 + 8 + VAULT_FILE_ID_SIZE));
    uint8_t *resp = malloc(buf_cap);
    if (!resp) {
        if (records) free(records);
        send_status_response(CMD_LIST_FILES, req_id, STATUS_ERR_NO_MEM);
        return;
    }

    resp[0] = STATUS_OK;
    uint32_t u32_count = (uint32_t)count;
    memcpy(resp + 1, &u32_count, 4);
    size_t offset = 5;

    for (size_t i = 0; i < count; i++) {
        uint16_t name_len = (uint16_t)strlen(records[i].filename);
        memcpy(resp + offset, &name_len, 2);
        offset += 2;
        memcpy(resp + offset, records[i].filename, name_len);
        offset += name_len;
        memcpy(resp + offset, &records[i].file_size, 8);
        offset += 8;
        memcpy(resp + offset, &records[i].modified_time, 8);
        offset += 8;
        memcpy(resp + offset, records[i].file_id, VAULT_FILE_ID_SIZE);
        offset += VAULT_FILE_ID_SIZE;
    }

    if (records) free(records);
    send_response(CMD_LIST_FILES, req_id, resp, (uint32_t)offset);
    free(resp);
}

static void handle_upload_begin(uint32_t req_id, const uint8_t *payload, uint32_t len) {
    if (!vault_storage_is_unlocked()) {
        send_status_response(CMD_UPLOAD_BEGIN, req_id, STATUS_ERR_LOCKED);
        return;
    }

    if (len < 2 + 1 + 8) {
        send_status_response(CMD_UPLOAD_BEGIN, req_id, STATUS_ERR_INVALID_ARG);
        return;
    }

    uint16_t name_len;
    memcpy(&name_len, payload, 2);
    if (len != 2 + name_len + 8 || name_len == 0 || name_len >= VAULT_MAX_FILENAME_LEN) {
        send_status_response(CMD_UPLOAD_BEGIN, req_id, STATUS_ERR_INVALID_ARG);
        return;
    }

    char filename[VAULT_MAX_FILENAME_LEN];
    memcpy(filename, payload + 2, name_len);
    filename[name_len] = '\0';

    uint64_t total_size;
    memcpy(&total_size, payload + 2 + name_len, 8);

    uint8_t file_id[VAULT_FILE_ID_SIZE];
    esp_err_t err = vault_storage_upload_begin(filename, total_size, file_id);
    if (err != ESP_OK) {
        send_status_response(CMD_UPLOAD_BEGIN, req_id, STATUS_ERR_STORAGE);
        return;
    }

    if (s_ui_transfer_cb) {
        uint32_t total_chunks = (uint32_t)((total_size + VAULT_CHUNK_SIZE - 1) / VAULT_CHUNK_SIZE);
        s_ui_transfer_cb("UPLOAD", filename, 0, total_chunks);
    }
    vault_status_led_set_state(VAULT_LED_TRANSFER);

    uint8_t resp[1 + VAULT_FILE_ID_SIZE + 4];
    resp[0] = STATUS_OK;
    memcpy(resp + 1, file_id, VAULT_FILE_ID_SIZE);
    uint32_t max_chunk = VAULT_CHUNK_SIZE;
    memcpy(resp + 1 + VAULT_FILE_ID_SIZE, &max_chunk, 4);

    send_response(CMD_UPLOAD_BEGIN, req_id, resp, sizeof(resp));
}

static void handle_upload_chunk(uint32_t req_id, const uint8_t *payload, uint32_t len) {
    if (!vault_storage_is_unlocked()) {
        send_status_response(CMD_UPLOAD_CHUNK, req_id, STATUS_ERR_LOCKED);
        return;
    }

    if (len < VAULT_FILE_ID_SIZE + 4) {
        send_status_response(CMD_UPLOAD_CHUNK, req_id, STATUS_ERR_INVALID_ARG);
        return;
    }

    const uint8_t *file_id = payload;
    uint32_t chunk_idx;
    memcpy(&chunk_idx, payload + VAULT_FILE_ID_SIZE, 4);

    const uint8_t *chunk_data = payload + VAULT_FILE_ID_SIZE + 4;
    size_t chunk_len = len - (VAULT_FILE_ID_SIZE + 4);

    esp_err_t err = vault_storage_upload_chunk(file_id, chunk_idx, chunk_data, chunk_len);
    if (err != ESP_OK) {
        send_status_response(CMD_UPLOAD_CHUNK, req_id, STATUS_ERR_STORAGE);
        return;
    }

    uint8_t resp[1 + 4];
    resp[0] = STATUS_OK;
    memcpy(resp + 1, &chunk_idx, 4);
    send_response(CMD_UPLOAD_CHUNK, req_id, resp, sizeof(resp));
}

static void handle_upload_commit(uint32_t req_id, const uint8_t *payload, uint32_t len) {
    if (!vault_storage_is_unlocked()) {
        send_status_response(CMD_UPLOAD_COMMIT, req_id, STATUS_ERR_LOCKED);
        return;
    }

    if (len != VAULT_FILE_ID_SIZE) {
        send_status_response(CMD_UPLOAD_COMMIT, req_id, STATUS_ERR_INVALID_ARG);
        return;
    }

    esp_err_t err = vault_storage_upload_commit(payload);
    if (err == ESP_OK) {
        vault_status_led_set_state(VAULT_LED_TRANSFER_COMPLETE);
    }
    send_status_response(CMD_UPLOAD_COMMIT, req_id, (err == ESP_OK) ? STATUS_OK : STATUS_ERR_STORAGE);
}

static void handle_download_begin(uint32_t req_id, const uint8_t *payload, uint32_t len) {
    if (!vault_storage_is_unlocked()) {
        send_status_response(CMD_DOWNLOAD_BEGIN, req_id, STATUS_ERR_LOCKED);
        return;
    }

    uint8_t target_id[VAULT_FILE_ID_SIZE];
    if (len == VAULT_FILE_ID_SIZE) {
        memcpy(target_id, payload, VAULT_FILE_ID_SIZE);
    } else if (len > 2) {
        uint16_t name_len;
        memcpy(&name_len, payload, 2);
        if (len == 2 + name_len && name_len < VAULT_MAX_FILENAME_LEN) {
            char name[VAULT_MAX_FILENAME_LEN];
            memcpy(name, payload + 2, name_len);
            name[name_len] = '\0';
            if (vault_storage_find_by_name(name, target_id) != ESP_OK) {
                send_status_response(CMD_DOWNLOAD_BEGIN, req_id, STATUS_ERR_NOT_FOUND);
                return;
            }
        } else {
            send_status_response(CMD_DOWNLOAD_BEGIN, req_id, STATUS_ERR_INVALID_ARG);
            return;
        }
    } else {
        send_status_response(CMD_DOWNLOAD_BEGIN, req_id, STATUS_ERR_INVALID_ARG);
        return;
    }

    uint64_t total_size = 0;
    uint32_t chunk_size = 0, total_chunks = 0;
    esp_err_t err = vault_storage_download_begin(target_id, &total_size, &chunk_size, &total_chunks);
    if (err != ESP_OK) {
        send_status_response(CMD_DOWNLOAD_BEGIN, req_id, (err == ESP_ERR_NOT_FOUND) ? STATUS_ERR_NOT_FOUND : STATUS_ERR_STORAGE);
        return;
    }

    if (s_ui_transfer_cb) {
        s_ui_transfer_cb("DOWNLOAD", "File", 0, total_chunks);
    }
    vault_status_led_set_state(VAULT_LED_TRANSFER);

    uint8_t resp[1 + VAULT_FILE_ID_SIZE + 8 + 4 + 4];
    resp[0] = STATUS_OK;
    memcpy(resp + 1, target_id, VAULT_FILE_ID_SIZE);
    memcpy(resp + 1 + VAULT_FILE_ID_SIZE, &total_size, 8);
    memcpy(resp + 1 + VAULT_FILE_ID_SIZE + 8, &chunk_size, 4);
    memcpy(resp + 1 + VAULT_FILE_ID_SIZE + 12, &total_chunks, 4);

    send_response(CMD_DOWNLOAD_BEGIN, req_id, resp, sizeof(resp));
}

static void handle_download_chunk(uint32_t req_id, const uint8_t *payload, uint32_t len) {
    if (!vault_storage_is_unlocked()) {
        send_status_response(CMD_DOWNLOAD_CHUNK, req_id, STATUS_ERR_LOCKED);
        return;
    }

    if (len < VAULT_FILE_ID_SIZE + 4) {
        send_status_response(CMD_DOWNLOAD_CHUNK, req_id, STATUS_ERR_INVALID_ARG);
        return;
    }

    const uint8_t *file_id = payload;
    uint32_t chunk_idx;
    memcpy(&chunk_idx, payload + VAULT_FILE_ID_SIZE, 4);

    uint8_t *plain = malloc(VAULT_CHUNK_SIZE);
    if (!plain) {
        send_status_response(CMD_DOWNLOAD_CHUNK, req_id, STATUS_ERR_NO_MEM);
        return;
    }

    size_t out_len = 0;
    esp_err_t err = vault_storage_download_chunk(file_id, chunk_idx, plain, &out_len);
    if (err != ESP_OK) {
        free(plain);
        send_status_response(CMD_DOWNLOAD_CHUNK, req_id, (err == ESP_ERR_INVALID_STATE) ? STATUS_ERR_AUTH_FAIL : STATUS_ERR_STORAGE);
        return;
    }

    uint8_t *resp = malloc(1 + 4 + out_len);
    if (!resp) {
        free(plain);
        send_status_response(CMD_DOWNLOAD_CHUNK, req_id, STATUS_ERR_NO_MEM);
        return;
    }

    resp[0] = STATUS_OK;
    memcpy(resp + 1, &chunk_idx, 4);
    if (out_len > 0) {
        memcpy(resp + 5, plain, out_len);
    }
    free(plain);

    send_response(CMD_DOWNLOAD_CHUNK, req_id, resp, (uint32_t)(5 + out_len));
    free(resp);
}

static void handle_download_end(uint32_t req_id, const uint8_t *payload, uint32_t len) {
    if (!vault_storage_is_unlocked()) {
        send_status_response(CMD_DOWNLOAD_END, req_id, STATUS_ERR_LOCKED); return;
    }
    if (len != VAULT_FILE_ID_SIZE) {
        send_status_response(CMD_DOWNLOAD_END, req_id, STATUS_ERR_INVALID_ARG); return;
    }
    esp_err_t err = vault_storage_download_end(payload);
    if (err == ESP_OK) vault_status_led_set_state(VAULT_LED_TRANSFER_COMPLETE);
    send_status_response(CMD_DOWNLOAD_END, req_id, err == ESP_OK ? STATUS_OK : STATUS_ERR_INVALID_ARG);
}

static void handle_delete_file(uint32_t req_id, const uint8_t *payload, uint32_t len) {
    if (!vault_storage_is_unlocked()) {
        send_status_response(CMD_DELETE_FILE, req_id, STATUS_ERR_LOCKED);
        return;
    }

    if (len != VAULT_FILE_ID_SIZE) {
        send_status_response(CMD_DELETE_FILE, req_id, STATUS_ERR_INVALID_ARG);
        return;
    }

    esp_err_t err = vault_storage_delete_file(payload);
    send_status_response(CMD_DELETE_FILE, req_id, (err == ESP_OK) ? STATUS_OK : ((err == ESP_ERR_NOT_FOUND) ? STATUS_ERR_NOT_FOUND : STATUS_ERR_STORAGE));
}

static void handle_lock(uint32_t req_id) {
    vault_storage_lock();
    vault_status_led_set_state(VAULT_LED_LOCKED);
    send_status_response(CMD_LOCK, req_id, STATUS_OK);
}

static void dispatch_frame(const protocol_header_t *hdr, const uint8_t *payload) {
    if(hdr->command==CMD_GET_USB_DIAGNOSTICS) {
        if(hdr->payload_len) { send_status_response(hdr->command,hdr->request_id,STATUS_ERR_INVALID_ARG);return; }
        char diagnostic[256];
        size_t n=vault_msc_diagnostics(diagnostic+1,sizeof(diagnostic)-1);
        diagnostic[0]=STATUS_OK;
        send_response(hdr->command,hdr->request_id,(uint8_t*)diagnostic,n+1);
        return;
    }
    if((vault_msc_exported() || vault_msc_busy()) && hdr->command!=CMD_GET_STATUS) {
        send_status_response(hdr->command,hdr->request_id,STATUS_ERR_BUSY);return;
    }
    if ((hdr->command == CMD_GET_STATUS || hdr->command == CMD_LIST_FILES || hdr->command == CMD_LOCK) && hdr->payload_len) {
        send_status_response(hdr->command, hdr->request_id, STATUS_ERR_INVALID_ARG); return;
    }
    switch (hdr->command) {
        case CMD_GET_STATUS:
            handle_get_status(hdr->request_id, payload, hdr->payload_len);
            break;
        case CMD_LIST_FILES:
            handle_list_files(hdr->request_id, payload, hdr->payload_len);
            break;
        case CMD_UPLOAD_BEGIN:
            handle_upload_begin(hdr->request_id, payload, hdr->payload_len);
            break;
        case CMD_UPLOAD_CHUNK:
            handle_upload_chunk(hdr->request_id, payload, hdr->payload_len);
            break;
        case CMD_UPLOAD_COMMIT:
            handle_upload_commit(hdr->request_id, payload, hdr->payload_len);
            break;
        case CMD_DOWNLOAD_BEGIN:
            handle_download_begin(hdr->request_id, payload, hdr->payload_len);
            break;
        case CMD_DOWNLOAD_CHUNK:
            handle_download_chunk(hdr->request_id, payload, hdr->payload_len);
            break;
        case CMD_DOWNLOAD_END:
            handle_download_end(hdr->request_id, payload, hdr->payload_len);
            break;
        case CMD_DELETE_FILE:
            handle_delete_file(hdr->request_id, payload, hdr->payload_len);
            break;
        case CMD_LOCK:
            handle_lock(hdr->request_id);
            break;
        default:
            ESP_LOGW(TAG, "Unknown command 0x%02x", hdr->command);
            send_status_response(hdr->command, hdr->request_id, STATUS_ERR_INVALID_ARG);
            break;
    }
}

static void cdc_rx_callback(int itf, cdcacm_event_t *event) {
    if (!s_rx_ringbuf) return;

    uint8_t temp[512];
    size_t rx_size = 0;
    while (tinyusb_cdcacm_read(itf, temp, sizeof(temp), &rx_size) == ESP_OK && rx_size > 0) {
        /* Apply brief backpressure instead of a 0-tick send: if the worker has
         * fallen behind, a non-blocking send would silently drop this chunk and
         * truncate a frame. Wait up to 20 ms for space; only if still full do we
         * drop (the frame CRC check then rejects it and the host retries). */
        if (xRingbufferSend(s_rx_ringbuf, temp, rx_size, pdMS_TO_TICKS(20)) != pdTRUE) {
            ESP_LOGW(TAG, "RX ringbuffer full; dropped %u bytes (host should retry)", (unsigned)rx_size);
        }
    }
}

static void protocol_task(void *pvParameters) {
    ESP_LOGI(TAG, "CDC Protocol Task started");

    uint8_t stream_buf[PROTOCOL_HEADER_SIZE + PROTOCOL_MAX_PAYLOAD + PROTOCOL_CRC_SIZE + 512];
    size_t stream_len = 0;

    while (s_running) {
        size_t item_size = 0;
        uint8_t *recv_data = (uint8_t *)xRingbufferReceiveUpTo(s_rx_ringbuf, &item_size, pdMS_TO_TICKS(50), sizeof(stream_buf) - stream_len);
        if (recv_data && item_size > 0) {
            memcpy(stream_buf + stream_len, recv_data, item_size);
            stream_len += item_size;
            vRingbufferReturnItem(s_rx_ringbuf, recv_data);
        }

        // Process frames from stream_buf
        while (stream_len >= PROTOCOL_HEADER_SIZE) {
            // Find magic "VLT1"
            if (memcmp(stream_buf, PROTOCOL_MAGIC, 4) != 0) {
                // Drop 1 byte and realign
                memmove(stream_buf, stream_buf + 1, stream_len - 1);
                stream_len--;
                continue;
            }

            protocol_header_t *hdr = (protocol_header_t *)stream_buf;
            if (hdr->version != PROTOCOL_VERSION || hdr->payload_len > PROTOCOL_MAX_PAYLOAD) {
                // Invalid header, drop magic to seek next
                memmove(stream_buf, stream_buf + 4, stream_len - 4);
                stream_len -= 4;
                continue;
            }

            size_t total_expected = PROTOCOL_HEADER_SIZE + hdr->payload_len + PROTOCOL_CRC_SIZE;
            if (stream_len < total_expected) {
                // Wait for more bytes
                break;
            }

            // Verify CRC32
            uint32_t expected_crc = compute_crc32(stream_buf, PROTOCOL_HEADER_SIZE + hdr->payload_len);
            uint32_t frame_crc;
            memcpy(&frame_crc, stream_buf + PROTOCOL_HEADER_SIZE + hdr->payload_len, PROTOCOL_CRC_SIZE);

            if (expected_crc != frame_crc) {
                ESP_LOGW(TAG, "CRC32 mismatch! Dropping corrupted frame");
                memmove(stream_buf, stream_buf + 4, stream_len - 4);
                stream_len -= 4;
                continue;
            }

            // Valid frame received!
            const uint8_t *payload = (hdr->payload_len > 0) ? (stream_buf + PROTOCOL_HEADER_SIZE) : NULL;
            vault_runtime_enter();
            vault_runtime_poll();
            dispatch_frame(hdr, payload);
            if (hdr->command != CMD_GET_STATUS && hdr->command != CMD_GET_USB_DIAGNOSTICS) vault_runtime_touch();
            vault_runtime_leave();

            // Consume frame from buffer
            memmove(stream_buf, stream_buf + total_expected, stream_len - total_expected);
            stream_len -= total_expected;
        }
    }

    xSemaphoreGive(s_stopped);
    vTaskDelete(NULL);
}

esp_err_t cdc_protocol_init(void) {
    if (s_running) return ESP_OK;

    init_crc32_table();

    s_rx_ringbuf = xRingbufferCreate(RX_BUFFER_SIZE, RINGBUF_TYPE_BYTEBUF);
    if (!s_rx_ringbuf) {
        ESP_LOGE(TAG, "Failed to create CDC Rx ringbuffer");
        return ESP_ERR_NO_MEM;
    }

    const tinyusb_config_t tusb_cfg = TINYUSB_DEFAULT_CONFIG();
    esp_err_t ret = tinyusb_driver_install(&tusb_cfg);
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "TinyUSB driver install failed: %d", ret);
        return ret;
    }

    tinyusb_config_cdcacm_t acm_cfg = {
        .cdc_port = TINYUSB_CDC_ACM_0,
        .callback_rx = &cdc_rx_callback,
        .callback_rx_wanted_char = NULL,
        .callback_line_state_changed = NULL,
        .callback_line_coding_changed = NULL
    };

    if (!tinyusb_cdcacm_initialized(TINYUSB_CDC_ACM_0)) {
        ESP_ERROR_CHECK(tinyusb_cdcacm_init(&acm_cfg));
    }

    s_stopped = xSemaphoreCreateBinary();
    if (!s_stopped) { tinyusb_cdcacm_deinit(TINYUSB_CDC_ACM_0); vRingbufferDelete(s_rx_ringbuf); s_rx_ringbuf = NULL; return ESP_ERR_NO_MEM; }
    s_running = true;
    if (xTaskCreate(protocol_task, "cdc_proto_task", STACK_SIZE, NULL, 5, &s_protocol_task_hdl) != pdPASS) {
        s_running = false;
        tinyusb_cdcacm_deinit(TINYUSB_CDC_ACM_0);
        vSemaphoreDelete(s_stopped); s_stopped = NULL;
        vRingbufferDelete(s_rx_ringbuf); s_rx_ringbuf = NULL;
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "CDC Protocol initialized and listening on CDC_ACM_0");
    return ESP_OK;
}

void cdc_protocol_set_ui_callback(cdc_ui_transfer_cb_t cb) {
    s_ui_transfer_cb = cb;
}

void cdc_protocol_deinit(void) {
    if (!s_running) return;
    tinyusb_cdcacm_deinit(TINYUSB_CDC_ACM_0);
    s_running = false;
    xSemaphoreTake(s_stopped, portMAX_DELAY);
    vSemaphoreDelete(s_stopped); s_stopped = NULL;
    s_protocol_task_hdl = NULL;
    if (s_rx_ringbuf) {
        vRingbufferDelete(s_rx_ringbuf);
        s_rx_ringbuf = NULL;
    }
}
