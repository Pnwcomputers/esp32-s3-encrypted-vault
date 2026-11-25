#ifndef VAULT_WEB_H
#define VAULT_WEB_H

#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*vault_web_ui_update_cb_t)(const char *status, const char *detail);

/**
 * Start the ad-hoc Wi-Fi web controller HTTP server.
 */
esp_err_t vault_web_start(void);
/* Call with the runtime gate held. */
void vault_web_revoke_session(void);

/**
 * Stop the web server.
 */
void vault_web_stop(void);

/**
 * Register a callback for LCD display status notifications from web events.
 */
void vault_web_set_display_cb(vault_web_ui_update_cb_t cb);

#ifdef __cplusplus
}
#endif

#endif // VAULT_WEB_H
