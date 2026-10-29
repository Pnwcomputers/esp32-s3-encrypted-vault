#ifndef VAULT_STORAGE_H
#define VAULT_STORAGE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"
#include "vault_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VAULT_MAX_FILENAME_LEN   128
#define VAULT_MAX_FILES          256
#ifndef VAULT_MOUNT_POINT
#define VAULT_MOUNT_POINT        "/sdcard"
#endif
#define VAULT_DIR                VAULT_MOUNT_POINT "/vault"
#define VAULT_FILES_DIR          VAULT_MOUNT_POINT "/vault/files"
#define VAULT_META_PATH          VAULT_MOUNT_POINT "/vault/vault.meta"
#define VAULT_INDEX_PATH         VAULT_MOUNT_POINT "/vault/index.enc"

#define VAULT_META_MAGIC         0x564C544B // "VLTK" in little-endian
#define VAULT_FILE_MAGIC         0x564C5446 // "VLTF"
#define VAULT_INDEX_MAGIC        0x564C5449 // "VLTI"

#pragma pack(push, 1)

typedef struct {
    uint8_t file_id[VAULT_FILE_ID_SIZE];
    char filename[VAULT_MAX_FILENAME_LEN];
    uint64_t file_size;
    uint64_t modified_time;
} vault_file_record_t;

typedef struct {
    uint32_t magic;           // "VLTK"
    uint8_t version;          // 1
    uint8_t reserved[3];
    uint32_t iterations;      // PBKDF2 iterations
    uint8_t salt[VAULT_SALT_SIZE];
    uint8_t iv[VAULT_IV_SIZE];
    uint8_t wrapped_dek[VAULT_KEY_SIZE];
    uint8_t tag[VAULT_TAG_SIZE];
} vault_meta_header_t;

typedef struct {
    uint32_t magic;           // "VLTF"
    uint8_t version;          // 1
    uint8_t reserved[3];
    uint8_t file_id[VAULT_FILE_ID_SIZE];
    uint64_t plaintext_size;
    uint32_t chunk_size;
    uint32_t total_chunks;
} vault_container_header_t;

typedef struct {
    uint32_t chunk_idx;
    uint32_t ciphertext_len;
    uint8_t iv[VAULT_IV_SIZE];
    uint8_t tag[VAULT_TAG_SIZE];
} vault_chunk_header_t;

#pragma pack(pop)

/**
 * Initialize vault filesystem structure on SD card.
 */
esp_err_t vault_storage_init(void);
void vault_storage_set_ready(bool ready);
bool vault_storage_is_ready(void);
/* Static, JSON-safe text explaining why storage is not ready; NULL when ready. */
void vault_storage_set_unavailable_reason(const char *reason);
const char *vault_storage_unavailable_reason(void);
/* Opens the encrypted USB image without exporting the session key. */
esp_err_t vault_storage_drive_open(bool create);
/* Verifies without altering an unlocked session; callers must serialize access. */
esp_err_t vault_storage_verify_pin(const char *pin);

/**
 * Check if the vault has been provisioned with a PIN.
 */
bool vault_storage_is_provisioned(void);

/**
 * Provision a brand new vault with a user-provided PIN.
 */
esp_err_t vault_storage_create(const char *pin);

/**
 * Unlock the vault with a user PIN.
 * Derives KEK and verifies DEK unwrapping.
 */
esp_err_t vault_storage_unlock(const char *pin);

/**
 * Check if vault is currently unlocked and DEK is in RAM.
 */
bool vault_storage_is_unlocked(void);

/**
 * Lock vault and securely erase DEK from RAM.
 */
void vault_storage_lock(void);

/**
 * Get SD card storage stats and file count.
 */
esp_err_t vault_storage_get_stats(uint32_t *total_mb, uint32_t *free_mb, uint32_t *file_count);

/**
 * Retrieve the array of file records in the vault.
 */
esp_err_t vault_storage_list_files(vault_file_record_t *records, size_t max_records, size_t *out_count);

/**
 * Start uploading a new file to the vault.
 */
esp_err_t vault_storage_upload_begin(const char *filename, uint64_t total_size, uint8_t *out_file_id);

/**
 * Write and encrypt an individual chunk of the uploading file.
 */
esp_err_t vault_storage_upload_chunk(const uint8_t *file_id, uint32_t chunk_idx, const uint8_t *data, size_t len);

/**
 * Finalize file upload, commit to encrypted index.
 */
esp_err_t vault_storage_upload_commit(const uint8_t *file_id);

/**
 * Abort an in-progress upload and clean up temporary files.
 */
esp_err_t vault_storage_upload_abort(const uint8_t *file_id);

/**
 * Start downloading a file from the vault.
 */
esp_err_t vault_storage_download_begin(const uint8_t *file_id,
                                       uint64_t *out_total_size,
                                       uint32_t *out_chunk_size,
                                       uint32_t *out_total_chunks);

/**
 * Read and decrypt an individual chunk of the downloading file.
 */
esp_err_t vault_storage_download_chunk(const uint8_t *file_id,
                                       uint32_t chunk_idx,
                                       uint8_t *out_plaintext,
                                       size_t *out_len);

/**
 * End download session.
 */
esp_err_t vault_storage_download_end(const uint8_t *file_id);

/**
 * Delete a file by file_id from the vault.
 */
esp_err_t vault_storage_delete_file(const uint8_t *file_id);

/**
 * Lookup file_id by filename (case-sensitive or insensitive).
 */
esp_err_t vault_storage_find_by_name(const char *filename, uint8_t *out_file_id);

/**
 * Get the record for a specific file_id.
 */
esp_err_t vault_storage_get_record(const uint8_t *file_id, vault_file_record_t *out_rec);

/**
 * Change the vault PIN, re-wrapping the DEK without re-encrypting files.
 */
esp_err_t vault_storage_change_pin(const char *old_pin, const char *new_pin);

#ifdef __cplusplus
}
#endif

#endif // VAULT_STORAGE_H
