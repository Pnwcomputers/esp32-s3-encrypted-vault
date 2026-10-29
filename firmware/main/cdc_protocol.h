#ifndef CDC_PROTOCOL_H
#define CDC_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PROTOCOL_MAGIC           "VLT1"
#define PROTOCOL_VERSION         1
#define PROTOCOL_MAX_PAYLOAD     4224 // 4096-byte chunk data + command metadata
#define PROTOCOL_HEADER_SIZE    14
#define PROTOCOL_CRC_SIZE        4

// Commands
#define CMD_GET_STATUS          0x01
#define CMD_GET_USB_DIAGNOSTICS 0x02
#define CMD_LIST_FILES          0x10
#define CMD_UPLOAD_BEGIN        0x20
#define CMD_UPLOAD_CHUNK        0x21
#define CMD_UPLOAD_COMMIT       0x22
#define CMD_DOWNLOAD_BEGIN      0x30
#define CMD_DOWNLOAD_CHUNK      0x31
#define CMD_DOWNLOAD_END        0x32
#define CMD_DELETE_FILE         0x40
#define CMD_LOCK                0x50

// Status responses
#define STATUS_OK               0x00
#define STATUS_ERR_LOCKED       0x01
#define STATUS_ERR_NOT_FOUND    0x02
#define STATUS_ERR_AUTH_FAIL    0x03
#define STATUS_ERR_STORAGE      0x04
#define STATUS_ERR_INVALID_ARG  0x05
#define STATUS_ERR_BUSY         0x06
#define STATUS_ERR_NO_MEM       0x07

#pragma pack(push, 1)

typedef struct {
    uint8_t magic[4];     // "VLT1"
    uint8_t version;      // 1
    uint8_t command;      // Command ID
    uint32_t request_id;  // Echoed back in response
    uint32_t payload_len; // Size of payload following
} protocol_header_t;

#pragma pack(pop)

typedef void (*cdc_ui_transfer_cb_t)(const char *op, const char *filename, uint32_t current_chunk, uint32_t total_chunks);

/**
 * Initialize and start the CDC protocol worker task and TinyUSB CDC ACM interface.
 */
esp_err_t cdc_protocol_init(void);

/**
 * Set an optional UI callback for file transfer progress notifications.
 */
void cdc_protocol_set_ui_callback(cdc_ui_transfer_cb_t cb);

/**
 * Stop and de-initialize the CDC protocol task.
 */
void cdc_protocol_deinit(void);

#ifdef __cplusplus
}
#endif

#endif // CDC_PROTOCOL_H
