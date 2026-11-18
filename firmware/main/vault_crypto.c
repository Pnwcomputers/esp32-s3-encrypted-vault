#include "vault_crypto.h"
#include <stdlib.h>
#include <string.h>
#include "esp_random.h"
#include "esp_log.h"
#include "mbedtls/gcm.h"
#include "mbedtls/sha256.h"

static const char *TAG = "vault_crypto";

void vault_secure_zero(void *v, size_t n) {
    if (!v || n == 0) return;
    volatile uint8_t *p = (volatile uint8_t *)v;
    while (n--) {
        *p++ = 0;
    }
}

esp_err_t vault_crypto_random(uint8_t *dest, size_t length) {
    if (!dest) return ESP_ERR_INVALID_ARG;
    esp_fill_random(dest, length);
    return ESP_OK;
}

/* PBKDF2-HMAC-SHA256 producing one 32-byte block (RFC 8018). The HMAC inner
 * and outer pad states are hashed once and cloned for every iteration, so each
 * iteration costs two SHA-256 compressions instead of the four a generic HMAC
 * reset/finish performs. The output is identical to standard PBKDF2. */
esp_err_t vault_crypto_kdf(const char *pin, size_t pin_len,
                           const uint8_t *salt, size_t salt_len,
                           uint32_t iterations,
                           uint8_t *out_key) {
    if (!pin || pin_len == 0 || !salt || salt_len == 0 || !out_key || iterations == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    static const uint8_t block_index[4] = {0, 0, 0, 1};
    uint8_t key[64] = {0}, pad[64], u[32], t[32];
    mbedtls_sha256_context inner, outer, work;
    mbedtls_sha256_init(&inner);
    mbedtls_sha256_init(&outer);
    mbedtls_sha256_init(&work);

    int ret = 0;
    if (pin_len > sizeof(key)) ret = mbedtls_sha256((const unsigned char *)pin, pin_len, key, 0);
    else memcpy(key, pin, pin_len);

    for (size_t i = 0; i < sizeof(pad); i++) pad[i] = key[i] ^ 0x36;
    if (!ret) ret = mbedtls_sha256_starts(&inner, 0);
    if (!ret) ret = mbedtls_sha256_update(&inner, pad, sizeof(pad));
    for (size_t i = 0; i < sizeof(pad); i++) pad[i] = key[i] ^ 0x5c;
    if (!ret) ret = mbedtls_sha256_starts(&outer, 0);
    if (!ret) ret = mbedtls_sha256_update(&outer, pad, sizeof(pad));

    /* U1 = HMAC(P, S || INT(1)) */
    if (!ret) {
        mbedtls_sha256_clone(&work, &inner);
        ret = mbedtls_sha256_update(&work, salt, salt_len);
    }
    if (!ret) ret = mbedtls_sha256_update(&work, block_index, sizeof(block_index));
    if (!ret) ret = mbedtls_sha256_finish(&work, u);
    if (!ret) {
        mbedtls_sha256_clone(&work, &outer);
        ret = mbedtls_sha256_update(&work, u, sizeof(u));
    }
    if (!ret) ret = mbedtls_sha256_finish(&work, u);
    memcpy(t, u, sizeof(t));

    /* Ui = HMAC(P, Ui-1); T = U1 ^ ... ^ Uc */
    for (uint32_t c = 1; !ret && c < iterations; c++) {
        mbedtls_sha256_clone(&work, &inner);
        ret = mbedtls_sha256_update(&work, u, sizeof(u));
        if (!ret) ret = mbedtls_sha256_finish(&work, u);
        if (!ret) {
            mbedtls_sha256_clone(&work, &outer);
            ret = mbedtls_sha256_update(&work, u, sizeof(u));
        }
        if (!ret) ret = mbedtls_sha256_finish(&work, u);
        for (size_t i = 0; i < sizeof(t); i++) t[i] ^= u[i];
    }

    if (!ret) memcpy(out_key, t, VAULT_KEY_SIZE);
    mbedtls_sha256_free(&inner);
    mbedtls_sha256_free(&outer);
    mbedtls_sha256_free(&work);
    vault_secure_zero(&inner, sizeof(inner));
    vault_secure_zero(&outer, sizeof(outer));
    vault_secure_zero(&work, sizeof(work));
    vault_secure_zero(key, sizeof(key));
    vault_secure_zero(pad, sizeof(pad));
    vault_secure_zero(u, sizeof(u));
    vault_secure_zero(t, sizeof(t));
    if (ret != 0) {
        ESP_LOGE(TAG, "PBKDF2 derivation failed: -0x%04x", -ret);
        return ESP_FAIL;
    }
    return ESP_OK;
}

static esp_err_t gcm_encrypt(mbedtls_gcm_context *gcm,
                             const uint8_t *iv, size_t iv_len,
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *input, size_t length,
                             uint8_t *output, uint8_t *tag, size_t tag_len) {
    /* ESP-IDF's accelerated GCM update requires non-null buffers even for an
     * empty message. Keep length zero so only the AAD and tag are processed. */
    uint8_t empty = 0;
    if (length == 0) input = output = &empty;
    int ret = mbedtls_gcm_crypt_and_tag(gcm, MBEDTLS_GCM_ENCRYPT, length, iv, iv_len,
                                        aad, aad_len, input, output, tag_len, tag);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_gcm_crypt_and_tag failed: -0x%04x", -ret);
        return ESP_FAIL;
    }
    return ESP_OK;
}

static esp_err_t gcm_decrypt(mbedtls_gcm_context *gcm,
                             const uint8_t *iv, size_t iv_len,
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *input, size_t length,
                             const uint8_t *tag, size_t tag_len, uint8_t *output) {
    uint8_t empty = 0;
    if (length == 0) input = output = &empty;
    int ret = mbedtls_gcm_auth_decrypt(gcm, length, iv, iv_len, aad, aad_len,
                                       tag, tag_len, input, output);
    if (ret == MBEDTLS_ERR_GCM_AUTH_FAILED) {
        return ESP_ERR_INVALID_STATE; // Tag mismatch (corrupted data or wrong key)
    } else if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_gcm_auth_decrypt failed: -0x%04x", -ret);
        return ESP_FAIL;
    }
    return ESP_OK;
}

static bool gcm_setkey(mbedtls_gcm_context *gcm, const uint8_t *key) {
    mbedtls_gcm_init(gcm);
    int ret = mbedtls_gcm_setkey(gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_gcm_setkey failed: -0x%04x", -ret);
        mbedtls_gcm_free(gcm);
        return false;
    }
    return true;
}

esp_err_t vault_crypto_aes_gcm_encrypt(const uint8_t *key,
                                       const uint8_t *iv, size_t iv_len,
                                       const uint8_t *aad, size_t aad_len,
                                       const uint8_t *input, size_t length,
                                       uint8_t *output,
                                       uint8_t *tag, size_t tag_len) {
    if (!key || !iv || !tag || (length > 0 && (!input || !output))) {
        return ESP_ERR_INVALID_ARG;
    }
    mbedtls_gcm_context gcm;
    if (!gcm_setkey(&gcm, key)) return ESP_FAIL;
    esp_err_t err = gcm_encrypt(&gcm, iv, iv_len, aad, aad_len, input, length, output, tag, tag_len);
    mbedtls_gcm_free(&gcm);
    return err;
}

esp_err_t vault_crypto_aes_gcm_decrypt(const uint8_t *key,
                                       const uint8_t *iv, size_t iv_len,
                                       const uint8_t *aad, size_t aad_len,
                                       const uint8_t *input, size_t length,
                                       const uint8_t *tag, size_t tag_len,
                                       uint8_t *output) {
    if (!key || !iv || !tag || (length > 0 && (!input || !output))) {
        return ESP_ERR_INVALID_ARG;
    }
    mbedtls_gcm_context gcm;
    if (!gcm_setkey(&gcm, key)) return ESP_FAIL;
    esp_err_t err = gcm_decrypt(&gcm, iv, iv_len, aad, aad_len, input, length, tag, tag_len, output);
    mbedtls_gcm_free(&gcm);
    return err;
}

struct vault_gcm {
    mbedtls_gcm_context gcm;
};

vault_gcm_t *vault_gcm_create(const uint8_t key[VAULT_KEY_SIZE]) {
    if (!key) return NULL;
    vault_gcm_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;
    if (!gcm_setkey(&ctx->gcm, key)) {
        vault_secure_zero(ctx, sizeof(*ctx));
        free(ctx);
        return NULL;
    }
    return ctx;
}

void vault_gcm_destroy(vault_gcm_t *ctx) {
    if (!ctx) return;
    mbedtls_gcm_free(&ctx->gcm);
    vault_secure_zero(ctx, sizeof(*ctx));
    free(ctx);
}

esp_err_t vault_gcm_encrypt(vault_gcm_t *ctx,
                            const uint8_t *iv, size_t iv_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *input, size_t length,
                            uint8_t *output, uint8_t *tag, size_t tag_len) {
    if (!ctx || !iv || !tag || (length > 0 && (!input || !output))) return ESP_ERR_INVALID_ARG;
    return gcm_encrypt(&ctx->gcm, iv, iv_len, aad, aad_len, input, length, output, tag, tag_len);
}

esp_err_t vault_gcm_decrypt(vault_gcm_t *ctx,
                            const uint8_t *iv, size_t iv_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *input, size_t length,
                            const uint8_t *tag, size_t tag_len, uint8_t *output) {
    if (!ctx || !iv || !tag || (length > 0 && (!input || !output))) return ESP_ERR_INVALID_ARG;
    return gcm_decrypt(&ctx->gcm, iv, iv_len, aad, aad_len, input, length, tag, tag_len, output);
}
