#pragma once
#include <stdbool.h>
#include "esp_err.h"
bool vault_msc_exported(void);
bool vault_msc_busy(void);
esp_err_t vault_msc_connect(void);
