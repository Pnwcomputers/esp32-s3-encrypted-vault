#pragma once
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"
bool vault_msc_exported(void);
bool vault_msc_busy(void);
esp_err_t vault_msc_connect(void);
size_t vault_msc_diagnostics(char *out,size_t size);
