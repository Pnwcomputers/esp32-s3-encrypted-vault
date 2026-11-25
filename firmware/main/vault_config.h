#ifndef VAULT_CONFIG_H
#define VAULT_CONFIG_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VAULT_DEFAULT_SSID      "MyEarPods"
#define VAULT_DEFAULT_PASS      "53cur3ty"
#define VAULT_DEFAULT_CHANNEL   1

typedef enum {
    VAULT_LED_MODE_NORMAL = 0,
    VAULT_LED_MODE_DIM,
    VAULT_LED_MODE_STEALTH   // Completely dark
} vault_led_mode_t;

typedef struct {
    char wifi_ssid[33];
    char wifi_pass[65];
    uint8_t wifi_channel;
    bool wifi_hidden;
    uint32_t auto_lock_sec;     // 0 = disabled, e.g. 300 = 5 min
    bool usb_enabled;           // USB CDC-ACM communication enabled
    vault_led_mode_t led_mode;  // Status LED mode
    uint8_t lcd_brightness;     // 10-100%
    uint16_t lcd_rotation;      // 0, 90, 180, 270
    /* Added after 1.1.0; must stay last. Blobs saved by older firmware end
     * before this field and load with it false. */
    bool usb_read_only;         // Default for "Enable SD card drive": write-blocked
} vault_config_t;
/* Size of the settings blob saved by firmware before usb_read_only existed. */
#define VAULT_CONFIG_LEGACY_SIZE offsetof(vault_config_t, usb_read_only)

/**
 * Initialize configuration system and load settings from NVS.
 * Applies defaults if first run.
 */
esp_err_t vault_config_init(void);

/**
 * Get current system configuration.
 */
void vault_config_get(vault_config_t *out_cfg);

/**
 * Save new configuration to NVS.
 */
esp_err_t vault_config_validate(const vault_config_t *cfg);

esp_err_t vault_config_save(const vault_config_t *new_cfg);

/**
 * Reset all configuration settings back to factory defaults.
 */
esp_err_t vault_config_reset_defaults(void);

#ifdef __cplusplus
}
#endif

#endif // VAULT_CONFIG_H
