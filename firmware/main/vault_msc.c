#include "vault_msc.h"
#include "vault_drive.h"
#include "vault_storage.h"
#include "vault_runtime.h"
#include "vault_config.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "tusb.h"
#include <string.h>
#include <stdio.h>

/* Cached drive writes are committed after this long without a new write. */
#define FLUSH_IDLE_US 1000000

static bool s_worker, s_changed, s_flusher;
static int64_t s_last_write;
static uint32_t s_reads,s_writes,s_errors,s_error_lba,s_error_size,s_max_ms;
static int s_error_code;
size_t vault_msc_diagnostics(char *out,size_t size) {
    if(!out || !size)return 0;
    int n=snprintf(out,size,"ready=%u reads=%lu writes=%lu errors=%lu error_lba=%lu error_bytes=%lu error=%d max_ms=%lu stage=%s",
        vault_drive_ready(),(unsigned long)s_reads,(unsigned long)s_writes,(unsigned long)s_errors,
        (unsigned long)s_error_lba,(unsigned long)s_error_size,s_error_code,
        (unsigned long)s_max_ms,vault_drive_last_error());
    return n<0?0:(size_t)n<size?(size_t)n:size-1;
}
static esp_err_t flush_drive(void) {
    int64_t started=esp_timer_get_time();
    esp_err_t err=vault_drive_flush();
    int64_t elapsed=esp_timer_get_time()-started;
    if(elapsed>=250000)
        ESP_LOGW("vault_msc","Slow USB cache flush: %lld ms (err %d)",
                 (long long)(elapsed/1000),(int)err);
    return err;
}
bool vault_msc_exported(void) { return vault_storage_is_unlocked() && vault_drive_ready(); }
bool vault_msc_busy(void) { return s_worker; }
static bool enabled(void) { vault_config_t cfg;vault_config_get(&cfg);return cfg.usb_enabled; }
static void create_task(void *arg) {
    unsigned batch=0;
    for(;;) {
        vault_runtime_enter();
        bool active=vault_storage_is_unlocked() && vault_drive_creating();
        esp_err_t err=active?vault_drive_create_step():ESP_ERR_INVALID_STATE;
        bool done=err!=ESP_OK || !vault_drive_creating();
        if(done) { s_worker=false;s_changed=vault_drive_ready(); }
        else vault_runtime_touch(); /* Creation is useful activity. */
        vault_runtime_leave();
        if(done) break;
        if(++batch%16==0) vTaskDelay(pdMS_TO_TICKS(1));
    }
    vTaskDelete(NULL);
}
static void flush_task(void *arg) {
    for(;;) {
        vTaskDelay(pdMS_TO_TICKS(250));
        vault_runtime_enter();
        if(vault_drive_ready() && vault_drive_dirty() && esp_timer_get_time()-s_last_write>=FLUSH_IDLE_US)
            (void)flush_drive(); /* On failure the drive closes and Windows sees no medium. */
        vault_runtime_leave();
    }
}
/* The drive is exported only from here (web "Enable SD card drive"), never
 * implicitly on unlock. */
esp_err_t vault_msc_connect(void) {
    if(!enabled() || !vault_storage_is_unlocked() || s_worker) return ESP_ERR_INVALID_STATE;
    if(!s_flusher) s_flusher=xTaskCreate(flush_task,"usb_drive_flush",4096,NULL,4,NULL)==pdPASS;
    if(!s_flusher) return ESP_ERR_NO_MEM;
    if(vault_drive_ready()) return ESP_OK;
    bool create=!vault_drive_exists();
    esp_err_t err=vault_storage_drive_open(create);
    if(err!=ESP_OK) return err;
    if(create) {
        s_worker=true;
        if(xTaskCreate(create_task,"usb_drive_create",4096,NULL,4,NULL)!=pdPASS) {
            s_worker=false;vault_drive_close();return ESP_ERR_NO_MEM;
        }
    } else s_changed=true;
    return ESP_OK;
}
/* Replace esp_tinyusb's physical-medium ownership hooks. The physical SD FAT
 * stays mounted by this app; USB can only reach the encrypted image below. */
void msc_storage_mount_to_usb(void) { }
void msc_storage_mount_to_app(void) {
    vault_runtime_enter();
    if(!s_worker) vault_drive_close();
    vault_runtime_leave();
}
uint8_t tud_msc_get_maxlun_cb(void) { return 1; }
void tud_msc_inquiry_cb(uint8_t lun,uint8_t vendor[8],uint8_t product[16],uint8_t rev[4]) {
    memcpy(vendor,"ESP32   ",8);memcpy(product,"Encrypted Vault ",16);memcpy(rev,"0101",4);
}
static bool medium(uint8_t lun) {
    if(lun || !vault_msc_exported()) { tud_msc_set_sense(lun,SCSI_SENSE_NOT_READY,0x3a,0);return false; }
    return true;
}
bool tud_msc_test_unit_ready_cb(uint8_t lun) {
    vault_runtime_enter();
    bool ready=medium(lun);
    if(ready && s_changed) { s_changed=false;tud_msc_set_sense(lun,SCSI_SENSE_UNIT_ATTENTION,0x28,0);ready=false; }
    vault_runtime_leave();return ready;
}
void tud_msc_capacity_cb(uint8_t lun,uint32_t *count,uint16_t *size) {
    vault_runtime_enter();*size=512;*count=medium(lun)?vault_drive_sector_count():0;vault_runtime_leave();
}
bool tud_msc_is_writable_cb(uint8_t lun) {
    vault_runtime_enter();bool ready=medium(lun);vault_runtime_leave();return ready;
}
static int32_t transfer(uint8_t lun,uint32_t lba,uint32_t offset,void *buffer,uint32_t size,bool write) {
    int64_t started=esp_timer_get_time();
    vault_runtime_enter();
    esp_err_t err=ESP_ERR_INVALID_STATE;
    if(medium(lun)) {
        uint64_t address=(uint64_t)lba*512+offset;
        err=write?vault_drive_write(address,buffer,size):vault_drive_read(address,buffer,size);
        if(err==ESP_OK) { vault_runtime_touch();if(write)s_last_write=esp_timer_get_time(); }
        else tud_msc_set_sense(lun,err==ESP_ERR_INVALID_ARG?SCSI_SENSE_ILLEGAL_REQUEST:SCSI_SENSE_MEDIUM_ERROR,
                               err==ESP_ERR_INVALID_ARG?0x21:0x11,0);
    }
    int64_t elapsed=esp_timer_get_time()-started;
    if(write)s_writes++;else s_reads++;
    if(err!=ESP_OK) {
        /* Preserve the first failure; later no-medium responses are fallout. */
        if(!s_errors) { s_error_lba=lba;s_error_size=size;s_error_code=err; }
        s_errors++;
    }
    if(elapsed/1000>s_max_ms)s_max_ms=elapsed/1000;
    vault_runtime_leave();
    if(elapsed>=250000)
        ESP_LOGW("vault_msc","Slow USB %s: LBA %lu offset %lu bytes %lu took %lld ms (err %d)",
                 write?"write":"read",(unsigned long)lba,(unsigned long)offset,
                 (unsigned long)size,(long long)(elapsed/1000),(int)err);
    return err==ESP_OK?(int32_t)size:-1;
}
int32_t tud_msc_read10_cb(uint8_t lun,uint32_t lba,uint32_t offset,void *buffer,uint32_t size) {
    return transfer(lun,lba,offset,buffer,size,false);
}
int32_t tud_msc_write10_cb(uint8_t lun,uint32_t lba,uint32_t offset,uint8_t *buffer,uint32_t size) {
    return transfer(lun,lba,offset,buffer,size,true);
}
bool tud_msc_start_stop_cb(uint8_t lun,uint8_t power,bool start,bool eject) {
    vault_runtime_enter();bool ok=!lun;
    if(ok && eject && !start) vault_drive_close();
    if(ok && eject && start && !vault_drive_ready()) {
        ok=vault_storage_is_unlocked() && vault_storage_drive_open(false)==ESP_OK;
        if(ok) s_changed=true;
    }
    vault_runtime_leave();return ok;
}
int32_t tud_msc_scsi_cb(uint8_t lun,const uint8_t cmd[16],void *buffer,uint16_t size) {
    /* SYNCHRONIZE CACHE commits the RAM write cache before succeeding. */
    if(cmd[0]==0x35) {
        vault_runtime_enter();bool ok=medium(lun) && flush_drive()==ESP_OK;vault_runtime_leave();
        if(!ok) tud_msc_set_sense(lun,SCSI_SENSE_MEDIUM_ERROR,0x0c,0);
        return ok?0:-1;
    }
    tud_msc_set_sense(lun,SCSI_SENSE_ILLEGAL_REQUEST,0x20,0);return -1;
}
