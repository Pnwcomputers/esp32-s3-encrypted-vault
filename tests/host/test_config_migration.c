/* Settings saved by 1.1.x firmware (before usb_read_only) still load. */
#include <assert.h>
#include <stdio.h>
#include "vault_config.c"
int main(void) {
    assert(VAULT_CONFIG_LEGACY_SIZE < sizeof(vault_config_t));
    vault_config_t old;set_defaults(&old);
    strcpy(old.wifi_ssid,"Saved SSID");old.auto_lock_sec=120;old.lcd_rotation=90;old.usb_read_only=true;
    assert(nvs_set_blob(0,"config_v1",&old,VAULT_CONFIG_LEGACY_SIZE)==ESP_OK); /* legacy-length blob */
    assert(vault_config_init()==ESP_OK);
    vault_config_t cfg;vault_config_get(&cfg);
    assert(!strcmp(cfg.wifi_ssid,"Saved SSID") && cfg.auto_lock_sec==120 && cfg.lcd_rotation==90 && !cfg.usb_read_only);
    cfg.usb_read_only=true;assert(vault_config_save(&cfg)==ESP_OK);
    s_inited=false;assert(vault_config_init()==ESP_OK);vault_config_get(&cfg);
    assert(cfg.usb_read_only && !strcmp(cfg.wifi_ssid,"Saved SSID"));
    puts("Settings migration checks passed (1.1.x settings blob loads; write-block default persists)");
    return 0;
}
