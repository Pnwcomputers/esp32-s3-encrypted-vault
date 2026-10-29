#include "vault_storage.h"
#include "vault_drive.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <stdlib.h>
#include "esp_vfs_fat.h"
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include "esp_log.h"
#include "esp_random.h"

static const char *TAG = "vault_storage";

static uint8_t s_vault_dek[VAULT_KEY_SIZE];
static bool s_vault_unlocked = false;
static bool s_ready = false;
static const char *s_unavailable_reason = "SD card unavailable";
void vault_storage_set_ready(bool ready) { s_ready = ready; }
bool vault_storage_is_ready(void) { return s_ready; }
void vault_storage_set_unavailable_reason(const char *reason) { if (reason) s_unavailable_reason = reason; }
const char *vault_storage_unavailable_reason(void) { return s_ready ? NULL : s_unavailable_reason; }

static vault_file_record_t s_index_records[VAULT_MAX_FILES];
static size_t s_index_count = 0;

// Active upload session
static bool s_upload_active = false;
static FILE *s_upload_fp = NULL;
static uint8_t s_upload_file_id[VAULT_FILE_ID_SIZE];
static char s_upload_filename[VAULT_MAX_FILENAME_LEN];
static uint64_t s_upload_total_size = 0;
static uint32_t s_upload_chunks_written = 0;
static uint32_t s_upload_total_chunks = 0;

// Active download session
static bool s_download_active = false;
static FILE *s_download_fp = NULL;
static uint8_t s_download_file_id[VAULT_FILE_ID_SIZE];
static uint64_t s_download_total_size = 0;
static uint32_t s_download_chunk_size = 0;
static uint32_t s_download_total_chunks = 0;

static void hex_encode_id(const uint8_t *id, char *out_hex) {
    for (int i = 0; i < VAULT_FILE_ID_SIZE; i++) {
        sprintf(out_hex + (i * 2), "%02x", id[i]);
    }
    out_hex[VAULT_FILE_ID_SIZE * 2] = '\0';
}

/* FAT rename cannot replace an existing file. Keep a recoverable previous copy. */
static esp_err_t replace_file(const char *tmp, const char *dest) {
    char backup[160];
    snprintf(backup, sizeof(backup), "%s.bak", dest);
    unlink(backup);
    if (rename(dest, backup) != 0 && errno != ENOENT) return ESP_FAIL;
    if (rename(tmp, dest) != 0) { rename(backup, dest); return ESP_FAIL; }
    unlink(backup);
    return ESP_OK;
}
static void recover_file(const char *dest) {
    char backup[160]; struct stat st;
    snprintf(backup, sizeof(backup), "%s.bak", dest);
    if (stat(dest, &st) != 0) rename(backup, dest);
}
static esp_err_t write_meta(const vault_meta_header_t *meta) {
    const char *tmp = VAULT_META_PATH ".tmp";
    FILE *fp = fopen(tmp, "wb");
    if (!fp) return ESP_FAIL;
    bool ok = fwrite(meta, 1, sizeof(*meta), fp) == sizeof(*meta);
    if (fflush(fp) != 0) ok = false;
    if (fsync(fileno(fp)) != 0) ok = false;
    if (fclose(fp) != 0) ok = false;
    if (!ok) { unlink(tmp); return ESP_FAIL; }
    return replace_file(tmp, VAULT_META_PATH);
}

static esp_err_t save_index(void) {
    if (!s_vault_unlocked) {
        return ESP_ERR_INVALID_STATE;
    }

    size_t payload_len = s_index_count * sizeof(vault_file_record_t);
    uint8_t *ciphertext = NULL;
    if (payload_len > 0) {
        ciphertext = malloc(payload_len);
        if (!ciphertext) {
            ESP_LOGE(TAG, "No memory to encrypt index");
            return ESP_ERR_NO_MEM;
        }
    }

    uint8_t iv[VAULT_IV_SIZE];
    uint8_t tag[VAULT_TAG_SIZE];
    vault_crypto_random(iv, sizeof(iv));

    uint32_t magic = VAULT_INDEX_MAGIC;
    uint32_t count = (uint32_t)s_index_count;

    if (payload_len > 0) {
        esp_err_t err = vault_crypto_aes_gcm_encrypt(
            s_vault_dek,
            iv, sizeof(iv),
            (const uint8_t *)&count, sizeof(count),
            (const uint8_t *)s_index_records, payload_len,
            ciphertext,
            tag, sizeof(tag)
        );
        if (err != ESP_OK) {
            free(ciphertext);
            ESP_LOGE(TAG, "Failed to encrypt index");
            return err;
        }
    } else {
        // Tag an empty payload
        esp_err_t err = vault_crypto_aes_gcm_encrypt(
            s_vault_dek,
            iv, sizeof(iv),
            (const uint8_t *)&count, sizeof(count),
            NULL, 0,
            NULL,
            tag, sizeof(tag)
        );
        if (err != ESP_OK) return err;
    }

    const char *tmp_path = VAULT_DIR "/index.tmp";
    FILE *fp = fopen(tmp_path, "wb");
    if (!fp) {
        if (ciphertext) free(ciphertext);
        ESP_LOGE(TAG, "Failed to open index.tmp for write");
        return ESP_FAIL;
    }

    uint8_t version = 1;
    bool ok = fwrite(&magic, 1, sizeof(magic), fp) == sizeof(magic) &&
        fwrite(&version, 1, 1, fp) == 1 &&
        fwrite(iv, 1, sizeof(iv), fp) == sizeof(iv) &&
        fwrite(&count, 1, sizeof(count), fp) == sizeof(count) &&
        fwrite(tag, 1, sizeof(tag), fp) == sizeof(tag) &&
        (!payload_len || fwrite(ciphertext, 1, payload_len, fp) == payload_len);
    free(ciphertext);
    if (fflush(fp) != 0) ok = false;
    if (fsync(fileno(fp)) != 0) ok = false;
    if (fclose(fp) != 0) ok = false;
    if (!ok) { unlink(tmp_path); return ESP_FAIL; }
    if (replace_file(tmp_path, VAULT_INDEX_PATH) != ESP_OK) return ESP_FAIL;

    ESP_LOGI(TAG, "Encrypted index saved (%u files)", (unsigned int)s_index_count);
    return ESP_OK;
}

static esp_err_t load_index(void) {
    s_index_count = 0;
    memset(s_index_records, 0, sizeof(s_index_records));

    FILE *fp = fopen(VAULT_INDEX_PATH, "rb");
    if (!fp) {
        return ESP_ERR_NOT_FOUND;
    }

    uint32_t magic = 0;
    uint8_t version = 0;
    uint8_t iv[VAULT_IV_SIZE];
    uint32_t count = 0;
    uint8_t tag[VAULT_TAG_SIZE];

    if (fread(&magic, 1, sizeof(magic), fp) != sizeof(magic) ||
        fread(&version, 1, 1, fp) != 1 ||
        fread(iv, 1, sizeof(iv), fp) != sizeof(iv) ||
        fread(&count, 1, sizeof(count), fp) != sizeof(count) ||
        fread(tag, 1, sizeof(tag), fp) != sizeof(tag)) {
        ESP_LOGE(TAG, "Corrupt index header");
        fclose(fp);
        return ESP_FAIL;
    }

    if (magic != VAULT_INDEX_MAGIC || version != 1) {
        ESP_LOGE(TAG, "Unsupported index version/magic");
        fclose(fp);
        return ESP_FAIL;
    }

    if (count > VAULT_MAX_FILES) {
        ESP_LOGE(TAG, "Index count %u exceeds limit", (unsigned int)count);
        fclose(fp);
        return ESP_FAIL;
    }

    if (count > 0) {
        size_t payload_len = count * sizeof(vault_file_record_t);
        uint8_t *ciphertext = malloc(payload_len);
        if (!ciphertext) {
            fclose(fp);
            return ESP_ERR_NO_MEM;
        }

        if (fread(ciphertext, 1, payload_len, fp) != payload_len) {
            ESP_LOGE(TAG, "Incomplete index ciphertext");
            free(ciphertext);
            fclose(fp);
            return ESP_FAIL;
        }
        if (fgetc(fp) != EOF || ferror(fp)) { free(ciphertext); fclose(fp); return ESP_FAIL; }
        fclose(fp);

        esp_err_t err = vault_crypto_aes_gcm_decrypt(
            s_vault_dek,
            iv, sizeof(iv),
            (const uint8_t *)&count, sizeof(count),
            ciphertext, payload_len,
            tag, sizeof(tag),
            (uint8_t *)s_index_records
        );
        free(ciphertext);

        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Index authentication decryption failed!");
            return ESP_ERR_INVALID_STATE;
        }
        s_index_count = count;
    } else {
        bool trailing = fgetc(fp) != EOF || ferror(fp);
        fclose(fp);
        if (trailing) return ESP_FAIL;
        esp_err_t err = vault_crypto_aes_gcm_decrypt(s_vault_dek, iv, sizeof(iv),
            (const uint8_t *)&count, sizeof(count), NULL, 0, tag, sizeof(tag), NULL);
        if (err != ESP_OK) return err;
    }
    for (size_t i = 0; i < s_index_count; i++)
        if (!memchr(s_index_records[i].filename, 0, VAULT_MAX_FILENAME_LEN)) return ESP_FAIL;

    ESP_LOGI(TAG, "Loaded %u file records from encrypted index", (unsigned int)s_index_count);
    return ESP_OK;
}

esp_err_t vault_storage_init(void) {
    if (mkdir(VAULT_DIR, 0775) != 0 && errno != EEXIST) return ESP_FAIL;
    if (mkdir(VAULT_FILES_DIR, 0775) != 0 && errno != EEXIST) return ESP_FAIL;
    recover_file(VAULT_META_PATH);
    recover_file(VAULT_INDEX_PATH);
    s_ready = true;
    return ESP_OK;
}

bool vault_storage_is_provisioned(void) {
    struct stat st;
    return stat(VAULT_META_PATH, &st) == 0; /* Corruption must never trigger re-provisioning. */
}

esp_err_t vault_storage_create(const char *pin) {
    if (!s_ready || vault_storage_is_provisioned()) return ESP_ERR_INVALID_STATE;
    if (!pin || strlen(pin) < 6 || strlen(pin) > 63) return ESP_ERR_INVALID_ARG;

    vault_meta_header_t meta = {0};
    meta.magic = VAULT_META_MAGIC;
    meta.version = 1;
    meta.iterations = VAULT_PBKDF2_ROUNDS;

    vault_crypto_random(meta.salt, VAULT_SALT_SIZE);
    vault_crypto_random(s_vault_dek, VAULT_KEY_SIZE);
    vault_crypto_random(meta.iv, VAULT_IV_SIZE);

    uint8_t kek[VAULT_KEY_SIZE];
    esp_err_t err = vault_crypto_kdf(pin, strlen(pin), meta.salt, VAULT_SALT_SIZE, meta.iterations, kek);
    if (err != ESP_OK) {
        vault_secure_zero(kek, sizeof(kek));
        return err;
    }

    err = vault_crypto_aes_gcm_encrypt(
        kek,
        meta.iv, VAULT_IV_SIZE,
        (const uint8_t *)&meta.magic, sizeof(meta.magic),
        s_vault_dek, VAULT_KEY_SIZE,
        meta.wrapped_dek,
        meta.tag, VAULT_TAG_SIZE
    );
    vault_secure_zero(kek, sizeof(kek));
    if (err != ESP_OK) {
        return err;
    }

    s_vault_unlocked = true;
    s_index_count = 0;
    err = save_index();
    if (err == ESP_OK) err = write_meta(&meta);
    if (err != ESP_OK) { vault_storage_lock(); return err; }

    ESP_LOGI(TAG, "New encrypted vault successfully provisioned");
    return ESP_OK;
}

static esp_err_t unwrap_dek(const char *pin, uint8_t *candidate) {
    if (!s_ready) return ESP_ERR_INVALID_STATE;
    if (!pin || !strlen(pin) || strlen(pin) > 63) return ESP_ERR_INVALID_ARG;

    FILE *fp = fopen(VAULT_META_PATH, "rb");
    if (!fp) {
        ESP_LOGW(TAG, "vault.meta not found");
        return ESP_ERR_NOT_FOUND;
    }

    vault_meta_header_t meta;
    if (fread(&meta, 1, sizeof(meta), fp) != sizeof(meta)) {
        fclose(fp);
        ESP_LOGE(TAG, "vault.meta read truncated");
        return ESP_FAIL;
    }
    fclose(fp);

    if (meta.magic != VAULT_META_MAGIC || meta.version != 1 ||
        meta.iterations < 1000 || meta.iterations > 1000000) {
        ESP_LOGE(TAG, "Unsupported vault format");
        return ESP_FAIL;
    }

    uint8_t kek[VAULT_KEY_SIZE];
    esp_err_t err = vault_crypto_kdf(pin, strlen(pin), meta.salt, VAULT_SALT_SIZE, meta.iterations, kek);
    if (err != ESP_OK) {
        vault_secure_zero(kek, sizeof(kek));
        return err;
    }

    err = vault_crypto_aes_gcm_decrypt(
        kek,
        meta.iv, VAULT_IV_SIZE,
        (const uint8_t *)&meta.magic, sizeof(meta.magic),
        meta.wrapped_dek, VAULT_KEY_SIZE,
        meta.tag, VAULT_TAG_SIZE,
        candidate
    );
    vault_secure_zero(kek, sizeof(kek));

    return err;
}

esp_err_t vault_storage_verify_pin(const char *pin) {
    uint8_t candidate[VAULT_KEY_SIZE];
    esp_err_t err = unwrap_dek(pin, candidate);
    vault_secure_zero(candidate, sizeof(candidate));
    return err;
}

esp_err_t vault_storage_unlock(const char *pin) {
    uint8_t candidate[VAULT_KEY_SIZE];
    esp_err_t err = unwrap_dek(pin, candidate);
    if (err == ESP_OK && !s_vault_unlocked) memcpy(s_vault_dek, candidate, sizeof(candidate));
    vault_secure_zero(candidate, sizeof(candidate));
    if (err != ESP_OK || s_vault_unlocked) return err;
    s_vault_unlocked = true;
    err = load_index();
    if (err != ESP_OK) vault_storage_lock();
    return err;
}

bool vault_storage_is_unlocked(void) {
    return s_vault_unlocked;
}

void vault_storage_lock(void) {
    vault_drive_close();
    vault_secure_zero(s_vault_dek, sizeof(s_vault_dek));
    s_vault_unlocked = false;

    if (s_upload_active) vault_storage_upload_abort(s_upload_file_id);
    s_upload_active = false;

    if (s_download_fp) {
        fclose(s_download_fp);
        s_download_fp = NULL;
    }
    s_download_active = false;

    memset(s_index_records, 0, sizeof(s_index_records));
    s_index_count = 0;

    ESP_LOGI(TAG, "Vault locked and session keys erased");
}

esp_err_t vault_storage_drive_open(bool create) {
    if(!s_ready || !s_vault_unlocked || s_upload_active || s_download_active) return ESP_ERR_INVALID_STATE;
    return vault_drive_open(s_vault_dek,create);
}

esp_err_t vault_storage_get_stats(uint32_t *total_mb, uint32_t *free_mb, uint32_t *file_count) {
    if (file_count) {
        *file_count = (uint32_t)s_index_count;
    }

    uint64_t total_bytes = 0, free_bytes = 0;
    if (s_ready && esp_vfs_fat_info(VAULT_MOUNT_POINT, &total_bytes, &free_bytes) == ESP_OK) {
        if (total_mb) *total_mb = (uint32_t)(total_bytes / (1024 * 1024));
        if (free_mb) *free_mb = (uint32_t)(free_bytes / (1024 * 1024));
        return ESP_OK;
    }

    if (total_mb) *total_mb = 0;
    if (free_mb) *free_mb = 0;
    return ESP_FAIL;
}

esp_err_t vault_storage_list_files(vault_file_record_t *records, size_t max_records, size_t *out_count) {
    if (!s_vault_unlocked) {
        return ESP_ERR_INVALID_STATE;
    }

    size_t count = records ? ((s_index_count < max_records) ? s_index_count : max_records) : s_index_count;
    if (records && count > 0) {
        memcpy(records, s_index_records, count * sizeof(vault_file_record_t));
    }
    if (out_count) {
        *out_count = count;
    }
    return ESP_OK;
}

esp_err_t vault_storage_upload_begin(const char *filename, uint64_t total_size, uint8_t *out_file_id) {
    /* Once capacity belongs to the USB volume, new legacy uploads must not
     * consume the space Windows was told is available. Existing files remain
     * readable/deletable after USB eject. */
    if (vault_drive_exists()) return ESP_ERR_INVALID_STATE;
    if (!s_vault_unlocked) return ESP_ERR_INVALID_STATE;
    if (!filename || strlen(filename) == 0 || !out_file_id) return ESP_ERR_INVALID_ARG;
    if (!strcmp(filename, ".") || !strcmp(filename, "..")) return ESP_ERR_INVALID_ARG;
    for (const unsigned char *p = (const unsigned char *)filename; *p; p++)
        if (*p < 32 || *p == '/' || *p == '\\') return ESP_ERR_INVALID_ARG;

    if (s_upload_active) return ESP_ERR_INVALID_STATE;
    if (strlen(filename) >= VAULT_MAX_FILENAME_LEN || total_size > UINT32_MAX) return ESP_ERR_INVALID_ARG;

    vault_crypto_random(s_upload_file_id, VAULT_FILE_ID_SIZE);
    memcpy(out_file_id, s_upload_file_id, VAULT_FILE_ID_SIZE);

    strncpy(s_upload_filename, filename, sizeof(s_upload_filename) - 1);
    s_upload_filename[sizeof(s_upload_filename) - 1] = '\0';

    s_upload_total_size = total_size;
    s_upload_chunks_written = 0;
    s_upload_total_chunks = (total_size == 0) ? 1 : (uint32_t)((total_size + VAULT_CHUNK_SIZE - 1) / VAULT_CHUNK_SIZE);

    char hex_id[VAULT_FILE_ID_SIZE * 2 + 1];
    hex_encode_id(s_upload_file_id, hex_id);

    char tmp_path[128];
    snprintf(tmp_path, sizeof(tmp_path), "%s/tmp_%s.bin", VAULT_FILES_DIR, hex_id);

    s_upload_fp = fopen(tmp_path, "wb");
    if (!s_upload_fp) {
        ESP_LOGE(TAG, "Failed to open upload tmp file: %s", tmp_path);
        return ESP_FAIL;
    }

    vault_container_header_t hdr = {0};
    hdr.magic = VAULT_FILE_MAGIC;
    hdr.version = 1;
    memcpy(hdr.file_id, s_upload_file_id, VAULT_FILE_ID_SIZE);
    hdr.plaintext_size = total_size;
    hdr.chunk_size = VAULT_CHUNK_SIZE;
    hdr.total_chunks = s_upload_total_chunks;

    if (fwrite(&hdr, 1, sizeof(hdr), s_upload_fp) != sizeof(hdr)) {
        fclose(s_upload_fp);
        s_upload_fp = NULL;
        unlink(tmp_path);
        return ESP_FAIL;
    }

    s_upload_active = true;
    ESP_LOGI(TAG, "Started upload for '%s' (%llu bytes, %u chunks)",
             filename, (unsigned long long)total_size, (unsigned int)s_upload_total_chunks);
    return ESP_OK;
}

esp_err_t vault_storage_upload_chunk(const uint8_t *file_id, uint32_t chunk_idx, const uint8_t *data, size_t len) {
    if (!s_vault_unlocked || !s_upload_active || !s_upload_fp) return ESP_ERR_INVALID_STATE;
    if (!file_id || memcmp(file_id, s_upload_file_id, VAULT_FILE_ID_SIZE) != 0) return ESP_ERR_INVALID_ARG;
    if (chunk_idx != s_upload_chunks_written) {
        ESP_LOGW(TAG, "Chunk sequence mismatch (expected %u, got %u)",
                 (unsigned int)s_upload_chunks_written, (unsigned int)chunk_idx);
        return ESP_ERR_INVALID_ARG;
    }

    size_t expected = (chunk_idx + 1 < s_upload_total_chunks) ? VAULT_CHUNK_SIZE :
        (size_t)(s_upload_total_size - (uint64_t)chunk_idx * VAULT_CHUNK_SIZE);
    if (chunk_idx >= s_upload_total_chunks || len != expected || (len && !data)) return ESP_ERR_INVALID_ARG;
    uint8_t iv[VAULT_IV_SIZE];
    uint8_t tag[VAULT_TAG_SIZE];
    vault_crypto_random(iv, sizeof(iv));

    struct {
        uint32_t magic;
        uint8_t file_id[VAULT_FILE_ID_SIZE];
        uint32_t chunk_idx;
        uint32_t len;
    } aad;
    aad.magic = VAULT_FILE_MAGIC;
    memcpy(aad.file_id, file_id, VAULT_FILE_ID_SIZE);
    aad.chunk_idx = chunk_idx;
    aad.len = (uint32_t)len;

    uint8_t *ciphertext = NULL;
    if (len > 0) {
        ciphertext = malloc(len);
        if (!ciphertext) return ESP_ERR_NO_MEM;
    }

    esp_err_t err = vault_crypto_aes_gcm_encrypt(
        s_vault_dek,
        iv, sizeof(iv),
        (const uint8_t *)&aad, sizeof(aad),
        data, len,
        ciphertext,
        tag, sizeof(tag)
    );
    if (err != ESP_OK) {
        if (ciphertext) free(ciphertext);
        return err;
    }

    vault_chunk_header_t chk = {0};
    chk.chunk_idx = chunk_idx;
    chk.ciphertext_len = (uint32_t)len;
    memcpy(chk.iv, iv, sizeof(iv));
    memcpy(chk.tag, tag, sizeof(tag));

    if (fwrite(&chk, 1, sizeof(chk), s_upload_fp) != sizeof(chk) ||
        (len > 0 && fwrite(ciphertext, 1, len, s_upload_fp) != len)) {
        if (ciphertext) free(ciphertext);
        return ESP_FAIL;
    }

    if (ciphertext) free(ciphertext);
    s_upload_chunks_written++;
    return ESP_OK;
}

esp_err_t vault_storage_upload_commit(const uint8_t *file_id) {
    if (!s_vault_unlocked || !s_upload_active || !s_upload_fp) return ESP_ERR_INVALID_STATE;
    if (!file_id || memcmp(file_id, s_upload_file_id, VAULT_FILE_ID_SIZE) != 0) return ESP_ERR_INVALID_ARG;

    if (s_upload_chunks_written != s_upload_total_chunks) return ESP_ERR_INVALID_SIZE;
    bool ok = fflush(s_upload_fp) == 0;
    if (fsync(fileno(s_upload_fp)) != 0) ok = false;
    if (fclose(s_upload_fp) != 0) ok = false;
    s_upload_fp = NULL;
    s_upload_active = false;
    if (!ok) { vault_storage_upload_abort(file_id); return ESP_FAIL; }

    char hex_id[VAULT_FILE_ID_SIZE * 2 + 1];
    hex_encode_id(file_id, hex_id);

    char tmp_path[128], final_path[128];
    snprintf(tmp_path, sizeof(tmp_path), "%s/tmp_%s.bin", VAULT_FILES_DIR, hex_id);
    snprintf(final_path, sizeof(final_path), "%s/%s.bin", VAULT_FILES_DIR, hex_id);

    unlink(final_path);
    if (rename(tmp_path, final_path) != 0) {
        ESP_LOGE(TAG, "Failed to rename committed file");
        unlink(tmp_path);
        return ESP_FAIL;
    }

    // Add or update in index
    int existing_idx = -1;
    for (size_t i = 0; i < s_index_count; i++) {
        if (memcmp(s_index_records[i].file_id, file_id, VAULT_FILE_ID_SIZE) == 0 ||
            strcmp(s_index_records[i].filename, s_upload_filename) == 0) {
            existing_idx = (int)i;
            break;
        }
    }

    int idx = (existing_idx >= 0) ? existing_idx : (int)s_index_count;
    if (existing_idx < 0) {
        if (s_index_count >= VAULT_MAX_FILES) {
            ESP_LOGE(TAG, "Vault file index full");
            unlink(final_path);
            return ESP_ERR_NO_MEM;
        }
        s_index_count++;
    }

    vault_file_record_t previous = s_index_records[idx];
    memcpy(s_index_records[idx].file_id, file_id, VAULT_FILE_ID_SIZE);
    strncpy(s_index_records[idx].filename, s_upload_filename, sizeof(s_index_records[idx].filename) - 1);
    s_index_records[idx].filename[sizeof(s_index_records[idx].filename) - 1] = '\0';
    s_index_records[idx].file_size = s_upload_total_size;
    s_index_records[idx].modified_time = (uint64_t)time(NULL);

    esp_err_t err = save_index();
    if (err != ESP_OK) {
        s_index_records[idx] = previous;
        if (existing_idx < 0) s_index_count--;
        unlink(final_path);
        return err;
    }
    if (existing_idx >= 0) {
        char old_id[VAULT_FILE_ID_SIZE * 2 + 1], old_path[128];
        hex_encode_id(previous.file_id, old_id);
        snprintf(old_path, sizeof(old_path), "%s/%s.bin", VAULT_FILES_DIR, old_id);
        unlink(old_path);
    }
    ESP_LOGI(TAG, "Upload committed for '%s' (ID: %s)", s_upload_filename, hex_id);
    return ESP_OK;
}

esp_err_t vault_storage_upload_abort(const uint8_t *file_id) {
    if (!file_id || memcmp(file_id, s_upload_file_id, VAULT_FILE_ID_SIZE)) return ESP_ERR_INVALID_ARG;
    if (s_upload_fp) {
        fclose(s_upload_fp);
        s_upload_fp = NULL;
    }
    s_upload_active = false;

    char hex_id[VAULT_FILE_ID_SIZE * 2 + 1];
    hex_encode_id(file_id, hex_id);

    char tmp_path[128];
    snprintf(tmp_path, sizeof(tmp_path), "%s/tmp_%s.bin", VAULT_FILES_DIR, hex_id);
    unlink(tmp_path);
    return ESP_OK;
}

esp_err_t vault_storage_download_begin(const uint8_t *file_id,
                                       uint64_t *out_total_size,
                                       uint32_t *out_chunk_size,
                                       uint32_t *out_total_chunks) {
    if (!s_vault_unlocked) return ESP_ERR_INVALID_STATE;
    if (!file_id) return ESP_ERR_INVALID_ARG;

    if (s_download_active) return ESP_ERR_INVALID_STATE;
    vault_file_record_t record;
    if (vault_storage_get_record(file_id, &record) != ESP_OK) return ESP_ERR_NOT_FOUND;

    char hex_id[VAULT_FILE_ID_SIZE * 2 + 1];
    hex_encode_id(file_id, hex_id);

    char path[128];
    snprintf(path, sizeof(path), "%s/%s.bin", VAULT_FILES_DIR, hex_id);

    s_download_fp = fopen(path, "rb");
    if (!s_download_fp) {
        ESP_LOGW(TAG, "File container not found: %s", path);
        return ESP_ERR_NOT_FOUND;
    }

    vault_container_header_t hdr;
    if (fread(&hdr, 1, sizeof(hdr), s_download_fp) != sizeof(hdr)) {
        fclose(s_download_fp);
        s_download_fp = NULL;
        return ESP_FAIL;
    }

    if (hdr.magic != VAULT_FILE_MAGIC || hdr.version != 1 ||
        memcmp(hdr.file_id, file_id, VAULT_FILE_ID_SIZE) || hdr.chunk_size != VAULT_CHUNK_SIZE ||
        hdr.plaintext_size != record.file_size || hdr.plaintext_size > UINT32_MAX ||
        hdr.total_chunks != (hdr.plaintext_size ? (hdr.plaintext_size + VAULT_CHUNK_SIZE - 1) / VAULT_CHUNK_SIZE : 1)) {
        fclose(s_download_fp);
        s_download_fp = NULL;
        return ESP_FAIL;
    }

    memcpy(s_download_file_id, file_id, VAULT_FILE_ID_SIZE);
    s_download_total_size = hdr.plaintext_size;
    s_download_chunk_size = hdr.chunk_size;
    s_download_total_chunks = hdr.total_chunks;
    s_download_active = true;

    if (out_total_size) *out_total_size = hdr.plaintext_size;
    if (out_chunk_size) *out_chunk_size = hdr.chunk_size;
    if (out_total_chunks) *out_total_chunks = hdr.total_chunks;

    return ESP_OK;
}

esp_err_t vault_storage_download_chunk(const uint8_t *file_id,
                                       uint32_t chunk_idx,
                                       uint8_t *out_plaintext,
                                       size_t *out_len) {
    if (!s_vault_unlocked || !s_download_active || !s_download_fp) return ESP_ERR_INVALID_STATE;
    if (!file_id || memcmp(file_id, s_download_file_id, VAULT_FILE_ID_SIZE) != 0) return ESP_ERR_INVALID_ARG;
    if (!out_plaintext || !out_len) return ESP_ERR_INVALID_ARG;

    vault_chunk_header_t chk;
    if (fread(&chk, 1, sizeof(chk), s_download_fp) != sizeof(chk)) {
        ESP_LOGE(TAG, "Failed to read chunk header %u", (unsigned int)chunk_idx);
        return ESP_FAIL;
    }

    if (chk.chunk_idx != chunk_idx) {
        ESP_LOGE(TAG, "Chunk index mismatch (expected %u, found %u)",
                 (unsigned int)chunk_idx, (unsigned int)chk.chunk_idx);
        return ESP_FAIL;
    }

    if (chunk_idx >= s_download_total_chunks) return ESP_ERR_INVALID_ARG;
    size_t expected = (chunk_idx + 1 < s_download_total_chunks) ? VAULT_CHUNK_SIZE :
        (size_t)(s_download_total_size - (uint64_t)chunk_idx * VAULT_CHUNK_SIZE);
    if (chk.ciphertext_len != expected || chk.ciphertext_len > VAULT_CHUNK_SIZE) return ESP_FAIL;
    uint8_t *ciphertext = NULL;
    if (chk.ciphertext_len > 0) {
        ciphertext = malloc(chk.ciphertext_len);
        if (!ciphertext) return ESP_ERR_NO_MEM;

        if (fread(ciphertext, 1, chk.ciphertext_len, s_download_fp) != chk.ciphertext_len) {
            free(ciphertext);
            return ESP_FAIL;
        }
    }

    struct {
        uint32_t magic;
        uint8_t file_id[VAULT_FILE_ID_SIZE];
        uint32_t chunk_idx;
        uint32_t len;
    } aad;
    aad.magic = VAULT_FILE_MAGIC;
    memcpy(aad.file_id, file_id, VAULT_FILE_ID_SIZE);
    aad.chunk_idx = chunk_idx;
    aad.len = chk.ciphertext_len;

    esp_err_t err = vault_crypto_aes_gcm_decrypt(
        s_vault_dek,
        chk.iv, sizeof(chk.iv),
        (const uint8_t *)&aad, sizeof(aad),
        ciphertext, chk.ciphertext_len,
        chk.tag, sizeof(chk.tag),
        out_plaintext
    );

    if (ciphertext) free(ciphertext);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Chunk %u AES-GCM verification failed!", (unsigned int)chunk_idx);
        return ESP_ERR_INVALID_STATE;
    }

    if (chunk_idx + 1 == s_download_total_chunks && (fgetc(s_download_fp) != EOF || ferror(s_download_fp))) {
        vault_secure_zero(out_plaintext, chk.ciphertext_len); return ESP_FAIL;
    }
    *out_len = chk.ciphertext_len;
    return ESP_OK;
}

esp_err_t vault_storage_download_end(const uint8_t *file_id) {
    if (!file_id || memcmp(file_id, s_download_file_id, VAULT_FILE_ID_SIZE)) return ESP_ERR_INVALID_ARG;
    if (s_download_fp) {
        fclose(s_download_fp);
        s_download_fp = NULL;
    }
    s_download_active = false;
    return ESP_OK;
}

esp_err_t vault_storage_delete_file(const uint8_t *file_id) {
    if (!s_vault_unlocked) return ESP_ERR_INVALID_STATE;

    int idx = -1;
    for (size_t i = 0; i < s_index_count; i++) {
        if (memcmp(s_index_records[i].file_id, file_id, VAULT_FILE_ID_SIZE) == 0) {
            idx = (int)i;
            break;
        }
    }

    if (idx < 0) {
        return ESP_ERR_NOT_FOUND;
    }

    char hex_id[VAULT_FILE_ID_SIZE * 2 + 1];
    hex_encode_id(file_id, hex_id);

    char path[128];
    snprintf(path, sizeof(path), "%s/%s.bin", VAULT_FILES_DIR, hex_id);
    vault_file_record_t deleted = s_index_records[idx];

    // Shift remaining records
    for (size_t i = idx; i < s_index_count - 1; i++) {
        s_index_records[i] = s_index_records[i + 1];
    }
    s_index_count--;
    memset(&s_index_records[s_index_count], 0, sizeof(vault_file_record_t));

    esp_err_t err = save_index();
    if (err != ESP_OK) {
        for (size_t i = s_index_count; i > (size_t)idx; i--) s_index_records[i] = s_index_records[i-1];
        s_index_records[idx] = deleted;
        s_index_count++;
        return err;
    }
    unlink(path);
    ESP_LOGI(TAG, "File ID %s deleted from vault", hex_id);
    return ESP_OK;
}

esp_err_t vault_storage_find_by_name(const char *filename, uint8_t *out_file_id) {
    if (!s_vault_unlocked || !filename || !out_file_id) return ESP_ERR_INVALID_STATE;

    for (size_t i = 0; i < s_index_count; i++) {
        if (strcmp(s_index_records[i].filename, filename) == 0) {
            memcpy(out_file_id, s_index_records[i].file_id, VAULT_FILE_ID_SIZE);
            return ESP_OK;
        }
    }
    return ESP_ERR_NOT_FOUND;
}

esp_err_t vault_storage_get_record(const uint8_t *file_id, vault_file_record_t *out_rec) {
    if (!s_vault_unlocked || !file_id || !out_rec) return ESP_ERR_INVALID_STATE;

    for (size_t i = 0; i < s_index_count; i++) {
        if (memcmp(s_index_records[i].file_id, file_id, VAULT_FILE_ID_SIZE) == 0) {
            memcpy(out_rec, &s_index_records[i], sizeof(vault_file_record_t));
            return ESP_OK;
        }
    }
    return ESP_ERR_NOT_FOUND;
}

esp_err_t vault_storage_change_pin(const char *old_pin, const char *new_pin) {
    if (!s_vault_unlocked) return ESP_ERR_INVALID_STATE;
    if (!new_pin || strlen(new_pin) < 6 || strlen(new_pin) > 63 || !old_pin || !*old_pin) return ESP_ERR_INVALID_ARG;
    esp_err_t check = vault_storage_verify_pin(old_pin);
    if (check != ESP_OK) return check;

    vault_meta_header_t meta = {0};
    meta.magic = VAULT_META_MAGIC;
    meta.version = 1;
    meta.iterations = VAULT_PBKDF2_ROUNDS;

    vault_crypto_random(meta.salt, VAULT_SALT_SIZE);
    vault_crypto_random(meta.iv, VAULT_IV_SIZE);

    uint8_t kek[VAULT_KEY_SIZE];
    esp_err_t err = vault_crypto_kdf(new_pin, strlen(new_pin), meta.salt, VAULT_SALT_SIZE, meta.iterations, kek);
    if (err != ESP_OK) {
        vault_secure_zero(kek, sizeof(kek));
        return err;
    }

    err = vault_crypto_aes_gcm_encrypt(
        kek,
        meta.iv, VAULT_IV_SIZE,
        (const uint8_t *)&meta.magic, sizeof(meta.magic),
        s_vault_dek, VAULT_KEY_SIZE,
        meta.wrapped_dek,
        meta.tag, VAULT_TAG_SIZE
    );
    vault_secure_zero(kek, sizeof(kek));
    if (err != ESP_OK) return err;

    err = write_meta(&meta);
    if (err != ESP_OK) return err;

    ESP_LOGI(TAG, "PIN successfully updated");
    return ESP_OK;
}
