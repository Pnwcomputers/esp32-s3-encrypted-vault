#pragma once
#include <stdint.h>
#include "esp_err.h"

esp_err_t vault_ble_start(void);
/* Returns -1 when there is no pairing prompt. */
int32_t vault_ble_passkey(void);
