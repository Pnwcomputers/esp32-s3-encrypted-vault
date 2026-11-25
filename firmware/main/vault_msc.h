#pragma once
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"
bool vault_msc_exported(void);
/* Clear host reload authorization on vault lock. Runtime gate required. */
void vault_msc_end_session(void);
bool vault_msc_busy(void);
/* Exports the drive. read_only write-blocks it for the host; while exported,
 * asking for the other mode returns ESP_ERR_NOT_SUPPORTED (eject first). */
esp_err_t vault_msc_connect(bool read_only);
/* True while exported write-blocked. */
bool vault_msc_read_only(void);
size_t vault_msc_diagnostics(char *out,size_t size);
