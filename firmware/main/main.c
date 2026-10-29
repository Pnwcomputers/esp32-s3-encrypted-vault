#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_wifi.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_http_server.h"
#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "driver/sdmmc_host.h"
#include "sdmmc_cmd.h"
#include "esp_vfs_fat.h"
#include "esp_heap_caps.h"
#include "esp_lcd_panel_io.h"
#include "esp_lcd_panel_vendor.h"
#include "esp_lcd_panel_ops.h"
#include "tinyusb.h"
#include "tinyusb_default_config.h"
#include "tinyusb_cdc_acm.h"
#include "esp_lvgl_port.h"
#include "lvgl.h"
#include "status_led.h"
#include "vault_config.h"
#include "vault_storage.h"
#include "vault_web.h"
#include "vault_runtime.h"
#include "cdc_protocol.h"
#include "driver/ledc.h"

static const char *TAG = "vault_main";

// --- WAVESHARE 1.47" HARDWARE PINS ---
#define LCD_MOSI  45
#define LCD_SCLK  40
#define LCD_CS    42
#define LCD_DC    41
#define LCD_RST   39
#define LCD_BL    48

#define SD_CLK    14
#define SD_CMD    15
#define SD_D0     16
#define SD_D1     18
#define SD_D2     17
#define SD_D3     21

static esp_lcd_panel_io_handle_t io_handle = NULL;
static esp_lcd_panel_handle_t panel_handle = NULL;
static lv_obj_t *ui_status_label = NULL;
static lv_obj_t *ui_prompt_label = NULL;
static vault_config_t s_boot_cfg;

static void display_status(const char *status, const char *detail) {
    lvgl_port_lock(0);
    lv_label_set_text(ui_status_label, status);
    lv_label_set_text(ui_prompt_label, detail);
    lvgl_port_unlock();
}

static void usb_progress(const char *op, const char *filename, uint32_t current, uint32_t total) {
    char detail[192];
    snprintf(detail, sizeof(detail), "%s\n%lu / %lu chunks", filename,
             (unsigned long)current, (unsigned long)total);
    display_status(op, detail);
}

void wifi_init_softap(void) {
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    wifi_config_t wifi_config = {0};
    memcpy(wifi_config.ap.ssid, s_boot_cfg.wifi_ssid, strlen(s_boot_cfg.wifi_ssid));
    memcpy(wifi_config.ap.password, s_boot_cfg.wifi_pass, strlen(s_boot_cfg.wifi_pass));
    wifi_config.ap.ssid_len = strlen(s_boot_cfg.wifi_ssid);
    wifi_config.ap.channel = s_boot_cfg.wifi_channel;
    wifi_config.ap.ssid_hidden = s_boot_cfg.wifi_hidden;
    wifi_config.ap.max_connection = 2;
    wifi_config.ap.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_LOGI(TAG, "Wi-Fi SoftAP active. SSID:%s", s_boot_cfg.wifi_ssid);
}

void init_lcd(void) {
    ESP_LOGI(TAG, "Initializing LCD hardware...");
    gpio_config_t bk_gpio_config = {
        .mode = GPIO_MODE_OUTPUT,
        .pin_bit_mask = (1ULL << LCD_BL)
    };
    gpio_config(&bk_gpio_config);

    spi_bus_config_t buscfg = {
        .sclk_io_num = LCD_SCLK,
        .mosi_io_num = LCD_MOSI,
        .miso_io_num = -1,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = 172 * 320 * 2 + 8
    };
    ESP_ERROR_CHECK(spi_bus_initialize(SPI2_HOST, &buscfg, SPI_DMA_CH_AUTO));

    esp_lcd_panel_io_spi_config_t io_config = {
        .dc_gpio_num = LCD_DC,
        .cs_gpio_num = LCD_CS,
        .pclk_hz = 20 * 1000 * 1000,
        .lcd_cmd_bits = 8,
        .lcd_param_bits = 8,
        .spi_mode = 0,
        .trans_queue_depth = 10,
    };
    ESP_ERROR_CHECK(esp_lcd_new_panel_io_spi((esp_lcd_spi_bus_handle_t)SPI2_HOST, &io_config, &io_handle));

    esp_lcd_panel_dev_config_t panel_config = {
        .reset_gpio_num = LCD_RST,
        .rgb_ele_order = LCD_RGB_ELEMENT_ORDER_RGB,
        .bits_per_pixel = 16,
    };
    ESP_ERROR_CHECK(esp_lcd_new_panel_st7789(io_handle, &panel_config, &panel_handle));

    ESP_ERROR_CHECK(esp_lcd_panel_reset(panel_handle));
    ESP_ERROR_CHECK(esp_lcd_panel_init(panel_handle));

    ESP_ERROR_CHECK(esp_lcd_panel_set_gap(panel_handle, 34, 0));
    ESP_ERROR_CHECK(esp_lcd_panel_invert_color(panel_handle, true));
    ESP_ERROR_CHECK(esp_lcd_panel_disp_on_off(panel_handle, true));

    const ledc_timer_config_t timer = {
        .speed_mode = LEDC_LOW_SPEED_MODE, .duty_resolution = LEDC_TIMER_10_BIT,
        .timer_num = LEDC_TIMER_0, .freq_hz = 5000, .clk_cfg = LEDC_AUTO_CLK
    };
    const ledc_channel_config_t channel = {
        .gpio_num = LCD_BL, .speed_mode = LEDC_LOW_SPEED_MODE,
        .channel = LEDC_CHANNEL_0, .timer_sel = LEDC_TIMER_0,
        .duty = (1023U * s_boot_cfg.lcd_brightness) / 100U
    };
    ESP_ERROR_CHECK(ledc_timer_config(&timer));
    ESP_ERROR_CHECK(ledc_channel_config(&channel));
}

static bool has_oem_name(const uint8_t *sector, const char *name) {
    return sector[510] == 0x55 && sector[511] == 0xAA && memcmp(sector + 3, name, 8) == 0;
}

/* Read-only look at the card after a failed mount so the user is told why.
 * The failed mount already released the host, so bring it up briefly here. */
static const char *sd_probe_filesystem(const sdmmc_slot_config_t *slot_config) {
    const char *reason = "SD card has no readable FAT32 filesystem; reformat it as FAT32";
    sdmmc_host_t host = SDMMC_HOST_DEFAULT();
    sdmmc_card_t *card = calloc(1, sizeof(*card));
    uint8_t *sector = heap_caps_malloc(512, MALLOC_CAP_DMA);
    if (!card || !sector || sdmmc_host_init() != ESP_OK) goto out;
    if (sdmmc_host_init_slot(host.slot, slot_config) == ESP_OK && sdmmc_card_init(&host, card) == ESP_OK &&
        sdmmc_read_sectors(card, sector, 0, 1) == ESP_OK) {
        /* Sector 0 is either a volume boot record (no partition table) or an
         * MBR whose first entry points at one; GPT cards keep the generic text. */
        if (!has_oem_name(sector, "EXFAT   ") && !has_oem_name(sector, "NTFS    ") &&
            sector[510] == 0x55 && sector[511] == 0xAA && sector[450] != 0x00 && sector[450] != 0xEE) {
            uint32_t lba = sector[454] | (sector[455] << 8) | (sector[456] << 16) | ((uint32_t)sector[457] << 24);
            if (lba == 0 || sdmmc_read_sectors(card, sector, lba, 1) != ESP_OK) memset(sector, 0, 512);
        }
        if (has_oem_name(sector, "EXFAT   ")) reason = "SD card is exFAT; reformat it as FAT32";
        else if (has_oem_name(sector, "NTFS    ")) reason = "SD card is NTFS; reformat it as FAT32";
    }
    sdmmc_host_deinit();
out:
    ESP_LOGE(TAG, "%s", reason);
    free(sector);
    free(card);
    return reason;
}

esp_err_t init_sd_card(void) {
    ESP_LOGI(TAG, "Initializing SD Card...");
    esp_vfs_fat_sdmmc_mount_config_t mount_config = {
        .format_if_mount_failed = false, .max_files = 5, .allocation_unit_size = 16 * 1024
    };
    sdmmc_card_t *card;
    sdmmc_host_t host = SDMMC_HOST_DEFAULT();
    
    sdmmc_slot_config_t slot_config = SDMMC_SLOT_CONFIG_DEFAULT();
    slot_config.width = 4; slot_config.clk = SD_CLK; slot_config.cmd = SD_CMD;
    slot_config.d0 = SD_D0; slot_config.d1 = SD_D1; slot_config.d2 = SD_D2; slot_config.d3 = SD_D3;

    /* 40 MHz high-speed bus; fall back to the 20 MHz default if the card or
     * wiring doesn't come up at that speed. */
    host.max_freq_khz = SDMMC_FREQ_HIGHSPEED;
    esp_err_t ret = esp_vfs_fat_sdmmc_mount("/sdcard", &host, &slot_config, &mount_config, &card);
    if (ret != ESP_OK && ret != ESP_FAIL) {
        ESP_LOGW(TAG, "SD high-speed init failed (%s); retrying at default speed.", esp_err_to_name(ret));
        host.max_freq_khz = SDMMC_FREQ_DEFAULT;
        ret = esp_vfs_fat_sdmmc_mount("/sdcard", &host, &slot_config, &mount_config, &card);
    }
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "SD mount failed (%s).", esp_err_to_name(ret));
        /* ESP_FAIL means the card answered but FATFS found no FAT volume. */
        vault_storage_set_unavailable_reason(ret == ESP_FAIL ? sd_probe_filesystem(&slot_config) :
            "SD card not detected; reseat it and restart");
    } else {
        ESP_LOGI(TAG, "SD Card mounted successfully.");
    }
    return ret;
}

void init_ui(void) {
    ESP_LOGI(TAG, "Initializing LVGL engine...");
    const lvgl_port_cfg_t lvgl_cfg = ESP_LVGL_PORT_INIT_CONFIG();
    ESP_ERROR_CHECK(lvgl_port_init(&lvgl_cfg));

    const lvgl_port_display_cfg_t disp_cfg = {
        .io_handle = io_handle,
        .panel_handle = panel_handle,
        .buffer_size = 172 * 40,
        .double_buffer = false,
        .hres = 172,
        .vres = 320,
        .monochrome = false,
        .color_format = LV_COLOR_FORMAT_RGB565,
        .flags = { 
            .buff_dma = true,
            .full_refresh = false
        }
    };
    
    lvgl_port_lock(0);

    lv_display_t *disp = lvgl_port_add_disp(&disp_cfg);
    if (!disp) { lvgl_port_unlock(); abort(); }

    // 180° rotation setting
    lv_display_set_rotation(disp, (lv_display_rotation_t)(s_boot_cfg.lcd_rotation / 90));

    lv_obj_t *scr = lv_screen_active();
    lv_obj_set_style_bg_color(scr, lv_color_hex(0x000000), LV_PART_MAIN);

    ui_status_label = lv_label_create(scr);
    lv_label_set_text(ui_status_label, "PAIRING MODE");
    lv_obj_set_style_text_color(ui_status_label, lv_color_hex(0xFF8800), LV_PART_MAIN);
    lv_obj_align(ui_status_label, LV_ALIGN_TOP_MID, 0, 20);

    ui_prompt_label = lv_label_create(scr);
    lv_label_set_text(ui_prompt_label, "Wi-Fi AP Active:\nMyEarPods\n\nIP Address:\n192.168.4.1");
    lv_obj_set_width(ui_prompt_label, 156);
    lv_obj_set_style_text_align(ui_prompt_label, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
    lv_obj_set_style_text_color(ui_prompt_label, lv_color_hex(0xFFFFFF), LV_PART_MAIN);
    lv_obj_align(ui_prompt_label, LV_ALIGN_CENTER, 0, 10);
    
    lvgl_port_unlock();
}

void app_main(void) {
    ESP_LOGI(TAG, "Booting ESP32 Vault...");
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        /* Fresh/unformatted or version-changed NVS: reformat once and retry so a
         * first boot on a blank chip recovers instead of aborting. */
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(vault_config_init());
    vault_config_get(&s_boot_cfg);
    ESP_ERROR_CHECK(vault_runtime_init());
    (void)vault_status_led_init();
    vault_status_led_set_mode(s_boot_cfg.led_mode);
    init_lcd();
    init_ui();
    bool sd_ok = init_sd_card() == ESP_OK;
    if (sd_ok && vault_storage_init() != ESP_OK) {
        sd_ok = false;
        vault_storage_set_unavailable_reason("SD card is read-only or full; vault folders could not be created");
    }
    vault_storage_set_ready(sd_ok);
    wifi_init_softap();
    vault_web_set_display_cb(display_status);
    ESP_ERROR_CHECK(vault_web_start());
    cdc_protocol_set_ui_callback(usb_progress);
    if (s_boot_cfg.usb_enabled) ESP_ERROR_CHECK(cdc_protocol_init());
    if (!sd_ok) vault_status_led_set_state(VAULT_LED_RECOVERY_ERROR);
    else vault_status_led_set_state(VAULT_LED_LOCKED);

    for (;;) {
        vault_runtime_enter();
        vault_runtime_poll();
        uint32_t total = 0, free_mb = 0, count = 0;
        vault_storage_get_stats(&total, &free_mb, &count);
        char detail[256];
        snprintf(detail, sizeof(detail), "%s\nhttp://192.168.4.1\n\n%lu / %lu MB free\n%lu files%s%s",
                 s_boot_cfg.wifi_ssid, (unsigned long)free_mb,
                 (unsigned long)total, (unsigned long)count,
                 sd_ok ? "" : "\n", sd_ok ? "" : vault_storage_unavailable_reason());
        display_status(vault_storage_is_unlocked() ? "VAULT UNLOCKED" : "VAULT LOCKED", detail);
        vault_runtime_leave();
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
