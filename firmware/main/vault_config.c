#include "vault_config.h"
#include <string.h>
#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"

static const char *TAG = "vault_config";
static const char *NVS_NAMESPACE = "vault_cfg";

static vault_config_t s_active_cfg;
static bool s_inited = false;

static void set_defaults(vault_config_t *cfg) {
    memset(cfg, 0, sizeof(vault_config_t));
    strncpy(cfg->wifi_ssid, VAULT_DEFAULT_SSID, sizeof(cfg->wifi_ssid) - 1);
    strncpy(cfg->wifi_pass, VAULT_DEFAULT_PASS, sizeof(cfg->wifi_pass) - 1);
    cfg->wifi_channel = VAULT_DEFAULT_CHANNEL;
    cfg->wifi_hidden = false;
    cfg->auto_lock_sec = 600; // 10 minutes default
    cfg->usb_enabled = true;
    cfg->led_mode = VAULT_LED_MODE_NORMAL;
    cfg->lcd_brightness = 100;
    cfg->lcd_rotation = 180;
    cfg->usb_read_only = false;
}

esp_err_t vault_config_init(void) {
    if (s_inited) return ESP_OK;

    set_defaults(&s_active_cfg);

    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &h);
    if (err == ESP_OK) {
        size_t len = sizeof(s_active_cfg.wifi_ssid);
        nvs_get_str(h, "ssid", s_active_cfg.wifi_ssid, &len);

        len = sizeof(s_active_cfg.wifi_pass);
        nvs_get_str(h, "pass", s_active_cfg.wifi_pass, &len);

        nvs_get_u8(h, "chan", &s_active_cfg.wifi_channel);

        uint8_t u8val = 0;
        if (nvs_get_u8(h, "hidden", &u8val) == ESP_OK) {
            s_active_cfg.wifi_hidden = (u8val != 0);
        }

        nvs_get_u32(h, "autolock", &s_active_cfg.auto_lock_sec);

        if (nvs_get_u8(h, "usb_en", &u8val) == ESP_OK) {
            s_active_cfg.usb_enabled = (u8val != 0);
        }

        if (nvs_get_u8(h, "led_mode", &u8val) == ESP_OK) {
            s_active_cfg.led_mode = (vault_led_mode_t)u8val;
        }

        nvs_get_u8(h, "bright", &s_active_cfg.lcd_brightness);
        nvs_get_u16(h, "rot", &s_active_cfg.lcd_rotation);

        vault_config_t saved;
        set_defaults(&saved);
        size_t saved_len = sizeof(saved);
        /* Accept the current layout or the 1.1.x one, which lacks trailing fields. */
        if (nvs_get_blob(h, "config_v1", &saved, &saved_len) == ESP_OK &&
            (saved_len == sizeof(saved) || saved_len == VAULT_CONFIG_LEGACY_SIZE)) {
            if (saved_len == VAULT_CONFIG_LEGACY_SIZE) saved.usb_read_only = false;
            if (vault_config_validate(&saved) == ESP_OK) s_active_cfg = saved;
        }
        nvs_close(h);
        ESP_LOGI(TAG, "Config loaded from NVS. SSID: %s", s_active_cfg.wifi_ssid);
    } else {
        ESP_LOGI(TAG, "No saved config in NVS; initialized with defaults");
    }

    if (vault_config_validate(&s_active_cfg) != ESP_OK) set_defaults(&s_active_cfg);
    s_inited = true;
    return ESP_OK;
}

void vault_config_get(vault_config_t *out_cfg) {
    if (!s_inited) vault_config_init();
    if (out_cfg) {
        memcpy(out_cfg, &s_active_cfg, sizeof(vault_config_t));
    }
}

esp_err_t vault_config_save(const vault_config_t *new_cfg) {
    if (vault_config_validate(new_cfg) != ESP_OK) return ESP_ERR_INVALID_ARG;

    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS for writing config");
        return err;
    }

    err = nvs_set_blob(h, "config_v1", new_cfg, sizeof(*new_cfg));
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);

    if (err == ESP_OK) {
        memcpy(&s_active_cfg, new_cfg, sizeof(vault_config_t));
        ESP_LOGI(TAG, "New configuration committed to NVS");
    }
    return err;
}

esp_err_t vault_config_reset_defaults(void) {
    vault_config_t defaults;
    set_defaults(&defaults);
    return vault_config_save(&defaults);
}

esp_err_t vault_config_validate(const vault_config_t *cfg) {
    if (!cfg) return ESP_ERR_INVALID_ARG;
    size_t ssid_len = strnlen(cfg->wifi_ssid, sizeof(cfg->wifi_ssid));
    size_t pass_len = strnlen(cfg->wifi_pass, sizeof(cfg->wifi_pass));
    if (ssid_len < 1 || ssid_len > 32 || pass_len < 8 || pass_len > 63 ||
        cfg->wifi_channel < 1 || cfg->wifi_channel > 11 ||
        cfg->auto_lock_sec > 86400 || (cfg->auto_lock_sec && cfg->auto_lock_sec < 30) ||
        cfg->led_mode < VAULT_LED_MODE_NORMAL || cfg->led_mode > VAULT_LED_MODE_STEALTH ||
        cfg->lcd_brightness < 10 || cfg->lcd_brightness > 100 ||
        cfg->lcd_rotation > 270 || cfg->lcd_rotation % 90) return ESP_ERR_INVALID_ARG;
    for (size_t i = 0; i < ssid_len; i++)
        if ((unsigned char)cfg->wifi_ssid[i] < 32) return ESP_ERR_INVALID_ARG;
    for (size_t i = 0; i < pass_len; i++)
        if ((unsigned char)cfg->wifi_pass[i] < 32 || (unsigned char)cfg->wifi_pass[i] > 126)
            return ESP_ERR_INVALID_ARG;
    return ESP_OK;
}
