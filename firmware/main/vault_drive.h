#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"
#define VAULT_DRIVE_BLOCK_SIZE 4096U
uint32_t vault_drive_sector_count(void);
/* All calls require the vault runtime gate. No physical SD sectors are exposed. */
esp_err_t vault_drive_open(const uint8_t key[32], bool create);
esp_err_t vault_drive_create_step(void);
/* Writes are cached in RAM; flush commits them durably. Close flushes first. */
esp_err_t vault_drive_flush(void);
bool vault_drive_dirty(void);
void vault_drive_close(void);
bool vault_drive_ready(void);
bool vault_drive_creating(void);
bool vault_drive_exists(void);
unsigned vault_drive_progress(void);
esp_err_t vault_drive_read(uint64_t offset, void *data, size_t size);
esp_err_t vault_drive_write(uint64_t offset, const void *data, size_t size);
