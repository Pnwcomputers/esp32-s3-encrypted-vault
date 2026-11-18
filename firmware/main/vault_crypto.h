#ifndef VAULT_CRYPTO_H
#define VAULT_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VAULT_KEY_SIZE       32  // 256-bit AES
#define VAULT_SALT_SIZE      32  // 256-bit salt
#define VAULT_IV_SIZE        12  // 96-bit nonce for AES-GCM
#define VAULT_TAG_SIZE       16  // 128-bit GCM authentication tag
#define VAULT_FILE_ID_SIZE   16  // 128-bit UUID/ID
#define VAULT_CHUNK_SIZE     4096 // 4 KB chunk size
#define VAULT_PBKDF2_ROUNDS  10000

/**
 * Securely erase sensitive memory buffer (compiler-barrier).
 */
void vault_secure_zero(void *v, size_t n);

/**
 * Generate cryptographically secure random bytes using ESP32 hardware RNG.
 */
esp_err_t vault_crypto_random(uint8_t *dest, size_t length);

/**
 * Derive a 256-bit key from a PIN string and salt using PBKDF2-HMAC-SHA256.
 */
esp_err_t vault_crypto_kdf(const char *pin, size_t pin_len,
                           const uint8_t *salt, size_t salt_len,
                           uint32_t iterations,
                           uint8_t *out_key);

/**
 * Encrypt plaintext using AES-256-GCM.
 * Generates ciphertext and 16-byte authentication tag.
 */
esp_err_t vault_crypto_aes_gcm_encrypt(const uint8_t *key,
                                       const uint8_t *iv, size_t iv_len,
                                       const uint8_t *aad, size_t aad_len,
                                       const uint8_t *input, size_t length,
                                       uint8_t *output,
                                       uint8_t *tag, size_t tag_len);

/**
 * Decrypt and verify ciphertext using AES-256-GCM.
 * Returns ESP_OK if authentication tag matches, or ESP_ERR_INVALID_STATE if corrupted/tampered.
 */
esp_err_t vault_crypto_aes_gcm_decrypt(const uint8_t *key,
                                       const uint8_t *iv, size_t iv_len,
                                       const uint8_t *aad, size_t aad_len,
                                       const uint8_t *input, size_t length,
                                       const uint8_t *tag, size_t tag_len,
                                       uint8_t *output);

/**
 * Reusable AES-256-GCM context for many records under one key. Keying once
 * avoids recomputing the GHASH key and table on every record. Not thread-safe;
 * callers serialize access. Destroy erases the key material.
 */
typedef struct vault_gcm vault_gcm_t;
vault_gcm_t *vault_gcm_create(const uint8_t key[VAULT_KEY_SIZE]);
void vault_gcm_destroy(vault_gcm_t *ctx);
esp_err_t vault_gcm_encrypt(vault_gcm_t *ctx,
                            const uint8_t *iv, size_t iv_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *input, size_t length,
                            uint8_t *output, uint8_t *tag, size_t tag_len);
/* Returns ESP_ERR_INVALID_STATE on authentication failure. */
esp_err_t vault_gcm_decrypt(vault_gcm_t *ctx,
                            const uint8_t *iv, size_t iv_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *input, size_t length,
                            const uint8_t *tag, size_t tag_len, uint8_t *output);

#ifdef __cplusplus
}
#endif

#endif // VAULT_CRYPTO_H
