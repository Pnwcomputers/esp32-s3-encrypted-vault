#include "vault_web.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "esp_log.h"
#include "esp_http_server.h"
#include "vault_storage.h"
#include "vault_crypto.h"
#include "status_led.h"
#include "vault_config.h"
#include "vault_runtime.h"
#include "vault_drive.h"
#include "vault_msc.h"
#include "cJSON.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "vault_web";

static httpd_handle_t s_server = NULL;
static vault_web_ui_update_cb_t s_display_cb = NULL;

static void hex_decode(const char *hex, uint8_t *out, size_t out_len) {
    for (size_t i = 0; i < out_len; i++) {
        char byte_str[3] = { hex[i * 2], hex[i * 2 + 1], '\0' };
        out[i] = (uint8_t)strtol(byte_str, NULL, 16);
    }
}

static void hex_encode(const uint8_t *in, size_t in_len, char *out) {
    for (size_t i = 0; i < in_len; i++) {
        sprintf(out + (i * 2), "%02x", in[i]);
    }
    out[in_len * 2] = '\0';
}

static bool extract_json_str(const char *json, const char *key, char *out, size_t max_len) {
    cJSON *root = cJSON_Parse(json);
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(root, key);
    bool ok = cJSON_IsString(v) && strlen(v->valuestring) < max_len;
    if (ok) strcpy(out, v->valuestring);
    cJSON_Delete(root);
    return ok;
}
static bool receive_body(httpd_req_t *req, char *buf, size_t capacity) {
    if (!req->content_len || req->content_len >= capacity) return false;
    size_t used = 0;
    while (used < req->content_len) {
        int n = httpd_req_recv(req, buf + used, req->content_len - used);
        if (n <= 0) return false;
        used += n;
    }
    buf[used] = 0;
    return true;
}
static esp_err_t json_error(httpd_req_t *req, const char *status, const char *message) {
    httpd_resp_set_status(req, status);
    httpd_resp_set_type(req, "application/json");
    char body[192];
    snprintf(body, sizeof(body), "{\"success\":false,\"error\":\"%s\"}", message);
    return httpd_resp_send(req, body, HTTPD_RESP_USE_STRLEN);
}
static esp_err_t send_json(httpd_req_t *req, cJSON *root) {
    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!body) return json_error(req, "500 Internal Server Error", "Out of memory");
    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_send(req, body, HTTPD_RESP_USE_STRLEN);
    free(body);
    return err;
}
static char s_token[65];
static int64_t s_next_auth;
static unsigned s_failures;
static bool authenticated(httpd_req_t *req) {
    char supplied[65];
    if (!vault_storage_is_unlocked()) { vault_secure_zero(s_token, sizeof(s_token)); return false; }
    if (!s_token[0] || httpd_req_get_hdr_value_str(req, "X-Vault-Token", supplied, sizeof(supplied)) != ESP_OK || strlen(supplied) != 64) return false;
    unsigned diff = 0;
    for (unsigned i = 0; i < 64; i++) diff |= (unsigned char)supplied[i] ^ (unsigned char)s_token[i];
    return diff == 0;
}
static bool check_credential(const char *pin) {
    if (esp_timer_get_time() < s_next_auth) return false;
    if (vault_storage_verify_pin(pin) == ESP_OK) { s_failures = 0; return true; }
    if (s_failures < 5) s_failures++;
    s_next_auth = esp_timer_get_time() + (int64_t)(1U << s_failures) * 1000000;
    return false;
}

static void url_decode(char *dst, const char *src, size_t max_len) {
    size_t i = 0;
    while (*src && i < max_len - 1) {
        if (*src == '+') {
            dst[i++] = ' ';
            src++;
        } else if (*src == '%' && *(src + 1) && *(src + 2)) {
            char hex[3] = { *(src + 1), *(src + 2), '\0' };
            dst[i++] = (char)strtol(hex, NULL, 16);
            src += 3;
        } else {
            dst[i++] = *src++;
        }
    }
    dst[i] = '\0';
}

extern const char vault_index_start[] asm("_binary_vault_index_html_start");

static esp_err_t root_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, vault_index_start, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t api_status_handler(httpd_req_t *req) {
    uint32_t total_mb = 0, free_mb = 0, file_count = 0;
    vault_storage_get_stats(&total_mb, &free_mb, &file_count);
    if (!authenticated(req)) total_mb = free_mb = file_count = 0;
    uint32_t used_mb = (total_mb > free_mb) ? (total_mb - free_mb) : 0;
    bool unlocked = authenticated(req);
    bool prov = vault_storage_is_provisioned();

    const char *sd_error = vault_storage_unavailable_reason();
    char resp[640];
    snprintf(resp, sizeof(resp),
             "{\"sd_error\":%s%s%s,\"provisioned\":%s,\"unlocked\":%s,\"total_mb\":%u,\"free_mb\":%u,\"used_mb\":%u,\"file_count\":%u,\"usb_drive_exists\":%s,\"usb_drive_ready\":%s,\"usb_drive_creating\":%s,\"usb_drive_mb\":%lu}",
             sd_error ? "\"" : "", sd_error ? sd_error : "null", sd_error ? "\"" : "",
             prov ? "true" : "false",
             unlocked ? "true" : "false",
             (unsigned int)total_mb, (unsigned int)free_mb, (unsigned int)used_mb, (unsigned int)file_count,
             unlocked && vault_drive_exists()?"true":"false",
             unlocked && vault_msc_exported()?"true":"false",
             unlocked && vault_msc_busy()?"true":"false",
             unlocked?(unsigned long)((uint64_t)vault_drive_sector_count()*512/(1024*1024)):0UL);

    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t api_unlock_handler(httpd_req_t *req) {
    char buf[256];
    if (!receive_body(req, buf, sizeof(buf))) return json_error(req, "400 Bad Request", "Invalid request body");

    char pin[64] = {0};
    if (!extract_json_str(buf, "pin", pin, sizeof(pin))) {
        httpd_resp_set_type(req, "application/json");
        return httpd_resp_send(req, "{\"success\":false,\"error\":\"Missing PIN\"}", HTTPD_RESP_USE_STRLEN);
    }

    bool creating = !vault_storage_is_provisioned();
    const char *validation_error = NULL;
    if (!vault_storage_is_ready()) validation_error = vault_storage_unavailable_reason();
    else if (creating && (strlen(pin) < 6 || strlen(pin) > 63))
        validation_error = "New credential must contain 6–63 UTF-8 bytes";
    if (validation_error || esp_timer_get_time() < s_next_auth) {
        vault_secure_zero(pin, sizeof(pin));
        vault_secure_zero(buf, sizeof(buf));
        if (validation_error) return json_error(req, "400 Bad Request", validation_error);
        return json_error(req, "429 Too Many Requests", "Wait before trying again");
    }
    esp_err_t err;
    if (creating) {
        err = vault_storage_create(pin);
    } else {
        err = vault_storage_unlock(pin);
    }

    vault_secure_zero(pin, sizeof(pin));
    vault_secure_zero(buf, sizeof(buf));
    httpd_resp_set_type(req, "application/json");
    if (err == ESP_OK) {
        s_failures = 0;
        uint8_t token[32];
        vault_crypto_random(token, sizeof(token));
        hex_encode(token, sizeof(token), s_token);
        vault_secure_zero(token, sizeof(token));
        vault_runtime_touch();
        vault_status_led_set_state(VAULT_LED_AUTH_SUCCESS);
        if (s_display_cb) s_display_cb("UNLOCKED", "Ad-Hoc Web Connected");
        char response[128];
        snprintf(response, sizeof(response), "{\"success\":true,\"token\":\"%s\"}", s_token);
        return httpd_resp_send(req, response, HTTPD_RESP_USE_STRLEN);
    } else if (creating || err != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "Vault %s failed: %d", creating ? "setup" : "unlock", (int)err);
        if (s_display_cb) s_display_cb("STORAGE ERROR", creating ? "Vault setup failed" : "Vault unlock failed");
        return json_error(req, "500 Internal Server Error", creating ?
            "Vault setup failed while encrypting or saving to the SD card" :
            "Vault could not be read or decrypted; check the SD card");
    } else {
        if (s_failures < 5) s_failures++;
        s_next_auth = esp_timer_get_time() + (int64_t)(1U << s_failures) * 1000000;
        vault_status_led_set_state(VAULT_LED_AUTH_FAILURE);
        if (s_display_cb) s_display_cb("AUTH FAILED", "Wrong PIN Entered");
        return httpd_resp_send(req, "{\"success\":false,\"error\":\"Incorrect PIN\"}", HTTPD_RESP_USE_STRLEN);
    }
}

static esp_err_t api_lock_handler(httpd_req_t *req) {
    vault_storage_lock();
    vault_secure_zero(s_token, sizeof(s_token));
    vault_status_led_set_state(VAULT_LED_LOCKED);
    if (s_display_cb) s_display_cb("LOCKED", "Web Lock Activated");
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, "{\"success\":true}", HTTPD_RESP_USE_STRLEN);
}

static esp_err_t api_usb_connect(httpd_req_t *req) {
    esp_err_t err=vault_msc_connect();
    if(err!=ESP_OK) return json_error(req,"409 Conflict",
        "USB drive could not be opened. Enable USB, finish transfers and check SD free space (at least 66 MB). Existing drive data is never reformatted automatically.");
    return httpd_resp_send(req,"{\"success\":true}",HTTPD_RESP_USE_STRLEN);
}

static esp_err_t api_files_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "application/json");
    if (!vault_storage_is_unlocked()) {
        return httpd_resp_send(req, "{\"files\":[],\"error\":\"locked\"}", HTTPD_RESP_USE_STRLEN);
    }

    size_t count = 0;
    vault_storage_list_files(NULL, 0, &count);

    httpd_resp_send_chunk(req, "{\"files\":[", HTTPD_RESP_USE_STRLEN);

    if (count > 0) {
        vault_file_record_t *records = malloc(count * sizeof(vault_file_record_t));
        if (records) {
            vault_storage_list_files(records, count, &count);
            for (size_t i = 0; i < count; i++) {
                char id_hex[VAULT_FILE_ID_SIZE * 2 + 1];
                hex_encode(records[i].file_id, VAULT_FILE_ID_SIZE, id_hex);

                cJSON *item = cJSON_CreateObject();
                cJSON_AddStringToObject(item, "id", id_hex);
                cJSON_AddStringToObject(item, "name", records[i].filename);
                cJSON_AddNumberToObject(item, "size", (double)records[i].file_size);
                cJSON_AddNumberToObject(item, "modified", (double)records[i].modified_time);
                char *text = cJSON_PrintUnformatted(item);
                cJSON_Delete(item);
                if (!text) { free(records); return ESP_FAIL; }
                if (i) httpd_resp_send_chunk(req, ",", 1);
                httpd_resp_send_chunk(req, text, HTTPD_RESP_USE_STRLEN);
                free(text);
            }
            free(records);
        }
    }

    httpd_resp_send_chunk(req, "]}", HTTPD_RESP_USE_STRLEN);
    return httpd_resp_send_chunk(req, NULL, 0);
}

static esp_err_t api_upload_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "application/json");
    if (!vault_storage_is_unlocked()) {
        return httpd_resp_send(req, "{\"success\":false,\"error\":\"Vault is locked\"}", HTTPD_RESP_USE_STRLEN);
    }

    char query[VAULT_MAX_FILENAME_LEN * 3 + 16];
    char filename[VAULT_MAX_FILENAME_LEN] = "upload.bin";
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        char enc_name[VAULT_MAX_FILENAME_LEN * 3];
        if (httpd_query_key_value(query, "name", enc_name, sizeof(enc_name)) == ESP_OK) {
            url_decode(filename, enc_name, sizeof(filename));
        }
    }

    uint64_t total_size = req->content_len;
    uint8_t file_id[VAULT_FILE_ID_SIZE];
    esp_err_t err = vault_storage_upload_begin(filename, total_size, file_id);
    if (err != ESP_OK) {
        return httpd_resp_send(req, "{\"success\":false,\"error\":\"Storage begin failed\"}", HTTPD_RESP_USE_STRLEN);
    }

    if (s_display_cb) s_display_cb("UPLOADING", filename);
    vault_status_led_set_state(VAULT_LED_TRANSFER);

    uint8_t *chunk_buf = malloc(VAULT_CHUNK_SIZE);
    if (!chunk_buf) {
        vault_status_led_set_state(VAULT_LED_UNLOCKED);
        vault_storage_upload_abort(file_id);
        return httpd_resp_send(req, "{\"success\":false,\"error\":\"Out of memory\"}", HTTPD_RESP_USE_STRLEN);
    }

    size_t remaining = total_size;
    uint32_t chunk_idx = 0;
    while (remaining > 0) {
        size_t to_read = (remaining > VAULT_CHUNK_SIZE) ? VAULT_CHUNK_SIZE : remaining;
        size_t filled = 0;
        while (filled < to_read) {
            int n = httpd_req_recv(req, (char *)chunk_buf + filled, to_read - filled);
            if (n <= 0) break;
            filled += n;
        }
        int recvd = (int)filled;
        if (filled != to_read) {
            ESP_LOGE(TAG, "Upload stream interrupted");
            vault_status_led_set_state(VAULT_LED_UNLOCKED);
            vault_secure_zero(chunk_buf, VAULT_CHUNK_SIZE);
            free(chunk_buf);
            vault_storage_upload_abort(file_id);
            return httpd_resp_send(req, "{\"success\":false,\"error\":\"Stream interrupted\"}", HTTPD_RESP_USE_STRLEN);
        }

        err = vault_storage_upload_chunk(file_id, chunk_idx, chunk_buf, recvd);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Chunk encryption write failed");
            vault_status_led_set_state(VAULT_LED_UNLOCKED);
            vault_secure_zero(chunk_buf, VAULT_CHUNK_SIZE);
            free(chunk_buf);
            vault_storage_upload_abort(file_id);
            return httpd_resp_send(req, "{\"success\":false,\"error\":\"Encryption write failed\"}", HTTPD_RESP_USE_STRLEN);
        }

        remaining -= recvd;
        chunk_idx++;
    }
    if (total_size == 0) err = vault_storage_upload_chunk(file_id, 0, NULL, 0);
    vault_secure_zero(chunk_buf, VAULT_CHUNK_SIZE);
    free(chunk_buf);
    if (err != ESP_OK) { vault_storage_upload_abort(file_id); return ESP_FAIL; }
    err = vault_storage_upload_commit(file_id);
    if (err != ESP_OK) {
        vault_status_led_set_state(VAULT_LED_UNLOCKED);
        return httpd_resp_send(req, "{\"success\":false,\"error\":\"Commit failed\"}", HTTPD_RESP_USE_STRLEN);
    }

    vault_status_led_set_state(VAULT_LED_TRANSFER_COMPLETE);
    if (s_display_cb) s_display_cb("UNLOCKED", "Upload Finished");

    char id_hex[VAULT_FILE_ID_SIZE * 2 + 1];
    hex_encode(file_id, VAULT_FILE_ID_SIZE, id_hex);

    char resp[128];
    snprintf(resp, sizeof(resp), "{\"success\":true,\"id\":\"%s\"}", id_hex);
    return httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t api_download_handler(httpd_req_t *req) {
    if (!vault_storage_is_unlocked()) {
        httpd_resp_set_type(req, "application/json");
        return httpd_resp_send(req, "{\"error\":\"Vault is locked\"}", HTTPD_RESP_USE_STRLEN);
    }

    char query[128];
    char id_hex[64] = {0};
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) != ESP_OK ||
        httpd_query_key_value(query, "id", id_hex, sizeof(id_hex)) != ESP_OK ||
        strlen(id_hex) != VAULT_FILE_ID_SIZE * 2) {
        httpd_resp_send_404(req);
        return ESP_FAIL;
    }

    if (strspn(id_hex, "0123456789abcdefABCDEF") != VAULT_FILE_ID_SIZE * 2)
        return json_error(req, "400 Bad Request", "Invalid file ID");
    uint8_t file_id[VAULT_FILE_ID_SIZE];
    hex_decode(id_hex, file_id, VAULT_FILE_ID_SIZE);

    vault_file_record_t rec;
    if (vault_storage_get_record(file_id, &rec) != ESP_OK) {
        httpd_resp_send_404(req);
        return ESP_FAIL;
    }

    uint64_t total_size = 0;
    uint32_t chunk_size = 0, total_chunks = 0;
    if (vault_storage_download_begin(file_id, &total_size, &chunk_size, &total_chunks) != ESP_OK) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    if (s_display_cb) s_display_cb("DOWNLOADING", rec.filename);
    vault_status_led_set_state(VAULT_LED_TRANSFER);

    httpd_resp_set_type(req, "application/octet-stream");
    char disp_hdr[256];
    char safe_name[VAULT_MAX_FILENAME_LEN];
    snprintf(safe_name, sizeof(safe_name), "%s", rec.filename);
    for (size_t i = 0; safe_name[i]; i++)
        if ((unsigned char)safe_name[i] < 32 || safe_name[i] == '"' || safe_name[i] == '\\') safe_name[i] = '_';
    snprintf(disp_hdr, sizeof(disp_hdr), "attachment; filename=\"%s\"", safe_name);
    httpd_resp_set_hdr(req, "Content-Disposition", disp_hdr);

    uint8_t *plain = malloc(VAULT_CHUNK_SIZE);
    if (!plain) {
        vault_status_led_set_state(VAULT_LED_UNLOCKED);
        vault_storage_download_end(file_id);
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    for (uint32_t i = 0; i < total_chunks; i++) {
        size_t out_len = 0;
        esp_err_t err = vault_storage_download_chunk(file_id, i, plain, &out_len);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Decryption error on chunk %u", (unsigned int)i);
            vault_status_led_set_state(VAULT_LED_UNLOCKED);
            vault_secure_zero(plain, VAULT_CHUNK_SIZE);
            free(plain);
            vault_storage_download_end(file_id);
            return ESP_FAIL;
        }

        if (out_len > 0) {
            if (httpd_resp_send_chunk(req, (const char *)plain, out_len) != ESP_OK) {
                vault_status_led_set_state(VAULT_LED_UNLOCKED);
                vault_secure_zero(plain, VAULT_CHUNK_SIZE);
                free(plain);
                vault_storage_download_end(file_id);
                return ESP_FAIL;
            }
        }
    }
    vault_secure_zero(plain, VAULT_CHUNK_SIZE);
    free(plain);
    vault_storage_download_end(file_id);
    vault_status_led_set_state(VAULT_LED_TRANSFER_COMPLETE);

    if (s_display_cb) s_display_cb("UNLOCKED", "Download Complete");
    return httpd_resp_send_chunk(req, NULL, 0);
}

static esp_err_t api_delete_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "application/json");
    if (!vault_storage_is_unlocked()) {
        return httpd_resp_send(req, "{\"success\":false,\"error\":\"Vault is locked\"}", HTTPD_RESP_USE_STRLEN);
    }

    char buf[256];
    if (!receive_body(req, buf, sizeof(buf))) return json_error(req, "400 Bad Request", "Invalid request body");

    char id_hex[64] = {0};
    if (!extract_json_str(buf, "id", id_hex, sizeof(id_hex)) || strlen(id_hex) != VAULT_FILE_ID_SIZE * 2) {
        return httpd_resp_send(req, "{\"success\":false,\"error\":\"Invalid ID\"}", HTTPD_RESP_USE_STRLEN);
    }

    if (strspn(id_hex, "0123456789abcdefABCDEF") != VAULT_FILE_ID_SIZE * 2)
        return json_error(req, "400 Bad Request", "Invalid file ID");
    uint8_t file_id[VAULT_FILE_ID_SIZE];
    hex_decode(id_hex, file_id, VAULT_FILE_ID_SIZE);

    esp_err_t err = vault_storage_delete_file(file_id);
    if (err == ESP_OK) {
        return httpd_resp_send(req, "{\"success\":true}", HTTPD_RESP_USE_STRLEN);
    } else {
        return httpd_resp_send(req, "{\"success\":false,\"error\":\"Delete failed\"}", HTTPD_RESP_USE_STRLEN);
    }
}

static esp_err_t api_change_pin_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "application/json");
    if (!vault_storage_is_unlocked()) {
        return httpd_resp_send(req, "{\"success\":false,\"error\":\"Vault is locked\"}", HTTPD_RESP_USE_STRLEN);
    }

    char buf[256];
    if (!receive_body(req, buf, sizeof(buf))) return json_error(req, "400 Bad Request", "Invalid request body");

    char old_pin[64] = {0}, new_pin[64] = {0};
    extract_json_str(buf, "old_pin", old_pin, sizeof(old_pin));
    extract_json_str(buf, "new_pin", new_pin, sizeof(new_pin));

    /* Scrub the submitted credentials and raw body on every exit path, not just
     * on success, so plaintext PIN bytes do not linger on the task stack. */
    esp_err_t resp;
    if (strlen(new_pin) < 6 || strlen(new_pin) > 63) {
        resp = httpd_resp_send(req, "{\"success\":false,\"error\":\"New PIN cannot be empty\"}", HTTPD_RESP_USE_STRLEN);
    } else if (!check_credential(old_pin)) {
        resp = json_error(req, "403 Forbidden", "Credential rejected or retry delay active");
    } else if (vault_storage_change_pin(old_pin, new_pin) == ESP_OK) {
        resp = httpd_resp_send(req, "{\"success\":true}", HTTPD_RESP_USE_STRLEN);
    } else {
        resp = httpd_resp_send(req, "{\"success\":false,\"error\":\"Old PIN incorrect\"}", HTTPD_RESP_USE_STRLEN);
    }
    vault_secure_zero(old_pin, sizeof(old_pin));
    vault_secure_zero(new_pin, sizeof(new_pin));
    vault_secure_zero(buf, sizeof(buf));
    return resp;
}

static esp_err_t api_settings_get(httpd_req_t *req) {
    vault_config_t cfg; vault_config_get(&cfg);
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "wifi_ssid", cfg.wifi_ssid);
    cJSON_AddNumberToObject(o, "wifi_channel", cfg.wifi_channel);
    cJSON_AddBoolToObject(o, "wifi_hidden", cfg.wifi_hidden);
    cJSON_AddNumberToObject(o, "auto_lock_sec", cfg.auto_lock_sec);
    cJSON_AddBoolToObject(o, "usb_enabled", cfg.usb_enabled);
    cJSON_AddNumberToObject(o, "led_mode", cfg.led_mode);
    cJSON_AddNumberToObject(o, "lcd_brightness", cfg.lcd_brightness);
    cJSON_AddNumberToObject(o, "lcd_rotation", cfg.lcd_rotation);
    return send_json(req, o); /* Never return the Wi-Fi password. */
}
static esp_err_t api_settings_post(httpd_req_t *req) {
    char body[768];
    if (!receive_body(req, body, sizeof(body))) return json_error(req, "400 Bad Request", "Invalid settings body");
    cJSON *o = cJSON_Parse(body);
    vault_secure_zero(body, sizeof(body));
    if (!cJSON_IsObject(o)) { cJSON_Delete(o); return json_error(req, "400 Bad Request", "Invalid JSON"); }
    cJSON *credential = cJSON_GetObjectItemCaseSensitive(o, "current_pin");
    if (!cJSON_IsString(credential) || !check_credential(credential->valuestring)) {
        cJSON_Delete(o); return json_error(req, "403 Forbidden", "Credential rejected or retry delay active");
    }
    /* The credential is verified; scrub its plaintext copy inside the parsed JSON
     * now rather than leaving it for cJSON_Delete (which frees without zeroing). */
    vault_secure_zero(credential->valuestring, strlen(credential->valuestring));
    vault_config_t cfg; vault_config_get(&cfg);
    bool valid = true;
    cJSON *v;
    #define STRING_FIELD(name, optional_empty) \
        v = cJSON_GetObjectItemCaseSensitive(o, #name); \
        if (v) { if (!cJSON_IsString(v) || strlen(v->valuestring) >= sizeof(cfg.name)) valid = false; \
            else if (!(optional_empty) || v->valuestring[0]) strcpy(cfg.name, v->valuestring); }
    #define NUMBER_FIELD(name, maxval) \
        v = cJSON_GetObjectItemCaseSensitive(o, #name); \
        if (v) { if (!cJSON_IsNumber(v) || !(v->valuedouble >= 0 && v->valuedouble <= (maxval)) || \
            v->valuedouble != (double)v->valueint) valid = false; else cfg.name = v->valueint; }
    #define BOOL_FIELD(name) \
        v = cJSON_GetObjectItemCaseSensitive(o, #name); \
        if (v) { if (!cJSON_IsBool(v)) valid = false; else cfg.name = cJSON_IsTrue(v); }
    STRING_FIELD(wifi_ssid, false)
    STRING_FIELD(wifi_pass, true)
    NUMBER_FIELD(wifi_channel, 11)
    NUMBER_FIELD(auto_lock_sec, 86400)
    NUMBER_FIELD(led_mode, 2)
    NUMBER_FIELD(lcd_brightness, 100)
    NUMBER_FIELD(lcd_rotation, 270)
    BOOL_FIELD(wifi_hidden)
    BOOL_FIELD(usb_enabled)
    #undef STRING_FIELD
    #undef NUMBER_FIELD
    #undef BOOL_FIELD
    cJSON_Delete(o);
    if (!valid || vault_config_validate(&cfg) != ESP_OK) return json_error(req, "400 Bad Request", "Invalid settings values");
    esp_err_t err = vault_config_save(&cfg);
    vault_secure_zero(&cfg, sizeof(cfg));
    if (err != ESP_OK) return json_error(req, "500 Internal Server Error", "Settings could not be saved");
    return httpd_resp_send(req, "{\"success\":true,\"restart_required\":true}", HTTPD_RESP_USE_STRLEN);
}
static void restart_task(void *arg) {
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(1000));
    esp_restart();
}
static esp_err_t api_restart(httpd_req_t *req) {
    if (xTaskCreate(restart_task, "vault_restart", 2048, NULL, 3, NULL) != pdPASS)
        return json_error(req, "500 Internal Server Error", "Restart unavailable");
    vault_storage_lock();
    vault_secure_zero(s_token, sizeof(s_token));
    return httpd_resp_send(req, "{\"success\":true}", HTTPD_RESP_USE_STRLEN);
}
/* All handlers run under the same gate as USB commands and automatic locking. */
static esp_err_t guarded_handler(httpd_req_t *req) {
    char host[64], origin[64];
    if (httpd_req_get_hdr_value_str(req, "Host", host, sizeof(host)) != ESP_OK ||
        (strcmp(host, "192.168.4.1") && strcmp(host, "192.168.4.1:80")))
        return json_error(req, "403 Forbidden", "Open http://192.168.4.1 directly");
    if (httpd_req_get_hdr_value_len(req, "Origin") &&
        (httpd_req_get_hdr_value_str(req, "Origin", origin, sizeof(origin)) != ESP_OK ||
         (strcmp(origin, "http://192.168.4.1") && strcmp(origin, "http://192.168.4.1:80"))))
        return json_error(req, "403 Forbidden", "Cross-origin requests are not allowed");
    vault_runtime_enter();
    vault_runtime_poll();
    if (req->method == HTTP_POST) httpd_resp_set_hdr(req, "Connection", "close");
    if (strcmp(req->uri, "/")) httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    httpd_resp_set_hdr(req, "X-Content-Type-Options", "nosniff");
    httpd_resp_set_hdr(req, "X-Frame-Options", "DENY");
    bool public = !strcmp(req->uri, "/") || !strcmp(req->uri, "/api/status") || !strcmp(req->uri, "/api/unlock");
    esp_err_t ret;
    char marker[8];
    if (req->method == HTTP_POST &&
        (httpd_req_get_hdr_value_str(req, "X-Vault-Request", marker, sizeof(marker)) != ESP_OK || strcmp(marker, "1"))) {
        ret = json_error(req, "403 Forbidden", "Same-origin controller required");
    } else if (!public && !authenticated(req)) {
        ret = json_error(req, "401 Unauthorized", "Unlock this browser session first");
    } else if(vault_drive_exists() && strncmp(req->uri,"/api/upload",11)==0) {
        ret=json_error(req,"409 Conflict","Use the SD card USB drive for new files; existing phone/client files can be downloaded or deleted after USB eject");
    } else if((vault_msc_exported() || vault_msc_busy()) &&
              (strncmp(req->uri,"/api/files",10)==0 || strncmp(req->uri,"/api/upload",11)==0 ||
               strncmp(req->uri,"/api/download",13)==0 || strncmp(req->uri,"/api/delete",11)==0 ||
               !strcmp(req->uri,"/api/lock") || !strcmp(req->uri,"/api/restart") ||
               !strcmp(req->uri,"/api/change_pin") || (!strcmp(req->uri,"/api/settings") && req->method==HTTP_POST))) {
        ret=json_error(req,"409 Conflict","Safely eject the USB drive in Windows before locking, changing settings or using phone/client files");
    } else {
        esp_err_t (*handler)(httpd_req_t *) = (esp_err_t (*)(httpd_req_t *))req->user_ctx;
        ret = handler(req);
        if (!public) vault_runtime_touch();
    }
    if (req->method == HTTP_POST) { vault_runtime_leave(); return ESP_FAIL; } /* Close even if body was rejected unread. */
    vault_runtime_leave();
    return ret;
}

esp_err_t vault_web_start(void) {
    if (s_server) return ESP_OK;

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_uri_handlers = 16;
    config.stack_size = 10240;

    esp_err_t ret = httpd_start(&s_server, &config);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start HTTP server: %d", ret);
        return ret;
    }

    httpd_uri_t uris[] = {
        { .uri = "/",           .method = HTTP_GET,  .handler = root_handler },
        { .uri = "/api/status", .method = HTTP_GET,  .handler = api_status_handler },
        { .uri = "/api/unlock", .method = HTTP_POST, .handler = api_unlock_handler },
        { .uri = "/api/lock",   .method = HTTP_POST, .handler = api_lock_handler },
        { .uri = "/api/files",  .method = HTTP_GET,  .handler = api_files_handler },
        { .uri = "/api/upload", .method = HTTP_POST, .handler = api_upload_handler },
        { .uri = "/api/download", .method = HTTP_GET, .handler = api_download_handler },
        { .uri = "/api/delete", .method = HTTP_POST, .handler = api_delete_handler },
        { .uri = "/api/change_pin", .method = HTTP_POST, .handler = api_change_pin_handler },
        { .uri = "/api/settings", .method = HTTP_GET, .handler = api_settings_get },
        { .uri = "/api/settings", .method = HTTP_POST, .handler = api_settings_post },
        { .uri = "/api/restart", .method = HTTP_POST, .handler = api_restart },
        { .uri = "/api/usb/connect", .method = HTTP_POST, .handler = api_usb_connect },
    };

    for (size_t i = 0; i < sizeof(uris) / sizeof(uris[0]); i++) {
        uris[i].user_ctx = (void *)uris[i].handler;
        uris[i].handler = guarded_handler;
        ret = httpd_register_uri_handler(s_server, &uris[i]);
        if (ret != ESP_OK) { vault_web_stop(); return ret; }
    }

    ESP_LOGI(TAG, "Ad-Hoc Web Controller HTTP server started");
    return ESP_OK;
}

void vault_web_stop(void) {
    if (s_server) {
        httpd_stop(s_server);
        s_server = NULL;
    }
}

void vault_web_set_display_cb(vault_web_ui_update_cb_t cb) {
    s_display_cb = cb;
}
