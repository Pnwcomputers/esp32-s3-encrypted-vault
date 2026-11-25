idf_component_register(
    SRCS "main.c" "status_led.c" "vault_config.c" "vault_runtime.c"
         "vault_crypto.c" "vault_storage.c" "vault_web.c" "cdc_protocol.c"
         "vault_drive.c" "vault_msc.c" "vault_ble.c"
    INCLUDE_DIRS "."
    EMBED_TXTFILES "vault_index.html"
    PRIV_REQUIRES driver led_strip esp_lcd sdmmc fatfs vfs esp_tinyusb
                  esp_lvgl_port nvs_flash esp_wifi esp_netif esp_event
                  esp_http_server esp_timer mbedtls json bt)

# esp_tinyusb 2.4.0's built-in MSC adapter exposes physical SD/flash media.
# Keep its descriptors/stack, but supply the encrypted-image adapter instead.
# The dependency is pinned; fail configuration if its source layout changes.
idf_component_get_property(usb_lib espressif__esp_tinyusb COMPONENT_LIB)
get_target_property(usb_sources ${usb_lib} SOURCES)
set(filtered_sources ${usb_sources})
list(FILTER filtered_sources EXCLUDE REGEX "(^|/)tinyusb_msc\\.c$")
if("${filtered_sources}" STREQUAL "${usb_sources}")
    message(FATAL_ERROR "Expected esp_tinyusb 2.4.0 MSC adapter source not found")
endif()
set_property(TARGET ${usb_lib} PROPERTY SOURCES ${filtered_sources})
