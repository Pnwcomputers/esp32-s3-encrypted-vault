#include "vault_ble.h"
#include "vault_msc.h"
#include "vault_drive.h"
#include "vault_runtime.h"
#include "vault_storage.h"
#include "vault_web.h"
#include "status_led.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "host/ble_hs.h"
#include "host/ble_sm.h"
#include "host/util/util.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"
#include <stdatomic.h>
#include <string.h>

#if CONFIG_BT_NIMBLE_SM_SC_ONLY != 1 || !defined(CONFIG_BT_NIMBLE_SM_SC) || \
    defined(CONFIG_BT_NIMBLE_SM_LEGACY) || defined(CONFIG_BT_NIMBLE_SM_SC_DEBUG_KEYS)
#error "Vault BLE unlock requires production LE Secure Connections only"
#endif

#define TAG "vault_ble"
#define VAULT_UUID(n) BLE_UUID128_INIT(0xa1, 0x46, 0x61, 0x77, 0xe1, 0x5f, 0xa2, 0xa8, \
                                      0x2d, 0x48, 0x55, 0xbc, n, 0x10, 0x9c, 0x39)
static const ble_uuid128_t service_uuid = VAULT_UUID(0x00);
static const ble_uuid128_t command_uuid = VAULT_UUID(0x01);
static const ble_uuid128_t status_uuid = VAULT_UUID(0x02);

enum result {
    IDLE, PENDING, EXPORTED, BAD_PIN, RETRY_LATER, NO_DRIVE, STORAGE_ERROR, EJECT_FIRST
};
static atomic_int s_result = IDLE;
static atomic_int s_passkey = -1;
static bool s_submitted; /* Owned by the NimBLE host. */
static uint8_t s_addr_type;
static TaskHandle_t s_worker;
static struct {
    bool read_only;
    char pin[64];
} s_request;

void ble_store_config_init(void);

int32_t vault_ble_passkey(void) { return atomic_load(&s_passkey); }

static enum result unlock_and_export(void) {
    if (!vault_storage_is_ready() || !vault_storage_is_provisioned()) return STORAGE_ERROR;
    if (!vault_runtime_auth_allowed()) return RETRY_LATER;

    int64_t started = esp_timer_get_time();
    bool was_locked = !vault_storage_is_unlocked();
    esp_err_t err = vault_storage_unlock(s_request.pin);
    int64_t authenticated = esp_timer_get_time();
    if (err != ESP_OK) {
        if (err == ESP_ERR_INVALID_STATE) {
            vault_runtime_auth_result(false);
            vault_status_led_set_state(VAULT_LED_AUTH_FAILURE);
            return BAD_PIN;
        }
        return STORAGE_ERROR;
    }
    vault_runtime_auth_result(true);
    if (was_locked) vault_web_revoke_session();
    vault_runtime_touch();
    vault_status_led_set_state(VAULT_LED_AUTH_SUCCESS);

    /* Provisioning a new multi-gigabyte image still requires the web UI. */
    if (!vault_drive_exists()) {
        if (was_locked) vault_storage_lock();
        return NO_DRIVE;
    }
    err = vault_msc_connect(s_request.read_only);
    ESP_LOGI(TAG, "Vault authentication %lld ms, USB export preparation %lld ms (err %d)",
             (long long)((authenticated - started) / 1000),
             (long long)((esp_timer_get_time() - authenticated) / 1000), (int)err);
    if (err == ESP_ERR_NOT_SUPPORTED) return EJECT_FIRST;
    if (err != ESP_OK && was_locked) vault_storage_lock();
    return err == ESP_OK ? EXPORTED : STORAGE_ERROR;
}

static void unlock_worker(void *arg) {
    (void)arg;
    for (;;) {
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
        vault_runtime_enter();
        vault_runtime_poll();
        enum result result = unlock_and_export();
        vault_secure_zero(s_request.pin, sizeof(s_request.pin));
        vault_runtime_leave();
        atomic_store(&s_result, result);
    }
}

static int access_vault(uint16_t conn, uint16_t attr, struct ble_gatt_access_ctxt *ctxt, void *arg) {
    (void)attr;
    (void)arg;
    struct ble_gap_conn_desc desc;
    if (ble_gap_conn_find(conn, &desc) || !desc.sec_state.encrypted ||
        !desc.sec_state.authenticated || desc.sec_state.key_size != 16)
        return BLE_ATT_ERR_INSUFFICIENT_AUTHEN;

    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
        uint8_t result = s_submitted ? atomic_load(&s_result) : IDLE;
        return os_mbuf_append(ctxt->om, &result, sizeof(result)) ? BLE_ATT_ERR_INSUFFICIENT_RES : 0;
    }

    size_t length = OS_MBUF_PKTLEN(ctxt->om);
    if (length < 2 || length > 64) return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    if (atomic_load(&s_result) == PENDING) return BLE_ATT_ERR_INSUFFICIENT_RES;
    uint8_t data[64];
    if (os_mbuf_copydata(ctxt->om, 0, length, data)) {
        vault_secure_zero(data, sizeof(data));
        return BLE_ATT_ERR_UNLIKELY;
    }
    if (data[0] > 1 || memchr(data + 1, 0, length - 1)) {
        vault_secure_zero(data, sizeof(data));
        return BLE_ATT_ERR_UNLIKELY;
    }
    s_request.read_only = data[0] == 1;
    memcpy(s_request.pin, data + 1, length - 1);
    s_request.pin[length - 1] = 0;
    vault_secure_zero(data, sizeof(data));
    s_submitted = true;
    atomic_store(&s_result, PENDING);
    xTaskNotifyGive(s_worker);
    return 0;
}

static const struct ble_gatt_svc_def services[] = {
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &service_uuid.u,
        .characteristics = (const struct ble_gatt_chr_def[]) {
            {.uuid = &command_uuid.u, .access_cb = access_vault,
             .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_AUTHEN, .min_key_size = 16},
            {.uuid = &status_uuid.u, .access_cb = access_vault,
             .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_AUTHEN, .min_key_size = 16},
            {0}
        },
    },
    {0}
};

static int gap_event(struct ble_gap_event *event, void *arg);
static void advertise(void) {
    struct ble_hs_adv_fields fields = {
        .flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP,
        .uuids128 = &service_uuid, .num_uuids128 = 1, .uuids128_is_complete = 1,
    };
    struct ble_gap_adv_params params = {
        .conn_mode = BLE_GAP_CONN_MODE_UND, .disc_mode = BLE_GAP_DISC_MODE_GEN,
    };
    int rc = ble_gap_adv_set_fields(&fields);
    if (!rc) rc = ble_gap_adv_start(s_addr_type, NULL, BLE_HS_FOREVER, &params, gap_event, NULL);
    if (rc) ESP_LOGW(TAG, "BLE advertising failed (%d)", rc);
}

static int gap_event(struct ble_gap_event *event, void *arg) {
    (void)arg;
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        s_submitted = false;
        if (event->connect.status) {
            advertise();
        } else {
            int rc = ble_gap_security_initiate(event->connect.conn_handle);
            if (rc && rc != BLE_HS_EALREADY)
                ble_gap_terminate(event->connect.conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        }
        break;
    case BLE_GAP_EVENT_PASSKEY_ACTION:
        if (event->passkey.params.action == BLE_SM_IOACT_DISP) {
            struct ble_sm_io io = {.action = BLE_SM_IOACT_DISP, .passkey = esp_random() % 1000000};
            atomic_store(&s_passkey, (int)io.passkey);
            if (ble_sm_inject_io(event->passkey.conn_handle, &io))
                ble_gap_terminate(event->passkey.conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        }
        break;
    case BLE_GAP_EVENT_ENC_CHANGE:
        atomic_store(&s_passkey, -1);
        if (event->enc_change.status)
            ble_gap_terminate(event->enc_change.conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        break;
    case BLE_GAP_EVENT_REPEAT_PAIRING:
        return BLE_GAP_REPEAT_PAIRING_IGNORE;
    case BLE_GAP_EVENT_DISCONNECT:
        atomic_store(&s_passkey, -1);
        advertise();
        break;
    case BLE_GAP_EVENT_ADV_COMPLETE:
        advertise();
        break;
    default:
        break;
    }
    return 0;
}

static void on_sync(void) {
    if (ble_hs_util_ensure_addr(0) == 0 && ble_hs_id_infer_auto(0, &s_addr_type) == 0)
        advertise();
}

static void host_task(void *arg) {
    (void)arg;
    nimble_port_run();
    nimble_port_freertos_deinit();
}

esp_err_t vault_ble_start(void) {
    esp_err_t err = nimble_port_init();
    if (err != ESP_OK) return err;
    ble_hs_cfg.sync_cb = on_sync;
    ble_hs_cfg.sm_io_cap = BLE_HS_IO_DISPLAY_ONLY;
    ble_hs_cfg.sm_bonding = 1;
    ble_hs_cfg.sm_mitm = 1;
    ble_hs_cfg.sm_sc = 1;
    ble_hs_cfg.sm_our_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;
    ble_hs_cfg.sm_their_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;
    ble_svc_gap_init();
    ble_svc_gatt_init();
    if (ble_svc_gap_device_name_set("ESP32 Vault") || ble_gatts_count_cfg(services) ||
        ble_gatts_add_svcs(services)) {
        nimble_port_deinit();
        return ESP_FAIL;
    }
    if (xTaskCreate(unlock_worker, "vault_ble_unlock", 8192, NULL, 4, &s_worker) != pdPASS) {
        nimble_port_deinit();
        return ESP_ERR_NO_MEM;
    }
    ble_store_config_init();
    nimble_port_freertos_init(host_task);
    return ESP_OK;
}
