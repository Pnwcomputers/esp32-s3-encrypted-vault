#pragma once
#include "esp_err.h"
#include <stdbool.h>
/* Serialize HTTP requests, USB commands and idle locking. Initialize before tasks. */
esp_err_t vault_runtime_init(void);
void vault_runtime_enter(void);
void vault_runtime_leave(void);
void vault_runtime_touch(void);
void vault_runtime_poll(void);
/* Shared PIN retry budget. Call under the runtime gate. */
bool vault_runtime_auth_allowed(void);
void vault_runtime_auth_result(bool accepted);
