#pragma once
#include <stdint.h>
#include <stdbool.h>
#define SCSI_SENSE_NOT_READY 2
#define SCSI_SENSE_MEDIUM_ERROR 3
#define SCSI_SENSE_ILLEGAL_REQUEST 5
#define SCSI_SENSE_UNIT_ATTENTION 6
bool tud_msc_set_sense(uint8_t lun,uint8_t key,uint8_t asc,uint8_t ascq);
bool tud_msc_test_unit_ready_cb(uint8_t lun);
void tud_msc_capacity_cb(uint8_t lun,uint32_t *count,uint16_t *size);
bool tud_msc_is_writable_cb(uint8_t lun);
int32_t tud_msc_read10_cb(uint8_t lun,uint32_t lba,uint32_t offset,void *buffer,uint32_t size);
int32_t tud_msc_write10_cb(uint8_t lun,uint32_t lba,uint32_t offset,uint8_t *buffer,uint32_t size);
bool tud_msc_start_stop_cb(uint8_t lun,uint8_t power,bool start,bool eject);
int32_t tud_msc_scsi_cb(uint8_t lun,const uint8_t cmd[16],void *buffer,uint16_t size);
#define SCSI_SENSE_DATA_PROTECT 7
