# Validation results — 2026-10-19

## USB mount performance changes — 2026-10-29

User reports Explorer stalls on nearly every enable with 64 GB and 128 GB
cards. Candidate mitigations add 16 KiB buffering to encrypted-drive file I/O,
enable FAT fast-seek in firmware defaults, and move the periodic LCD update
outside the runtime gate used by USB. Slow USB transfer and cache-flush timing
is logged at 250 ms to distinguish I/O stalls from expected throughput limits.
These changes preserve the on-card layout and do not require reformatting.

The 17 portable Python checks pass. A fresh Windows ESP-IDF 5.5.5 target
build with GCC 14.2.0 completed without compiler warnings or errors. The
application image is 1,402,096 bytes; generated configuration confirms 16 MB
flash, octal PSRAM, FAT fast-seek and a 256-word cluster-link map. Native C
host regressions were not run.

A connected ESP32-S3 revision 0.2 with 16 MB flash and 8 MB PSRAM was backed
up before flashing. Only the application at 0x10000 was updated, preserving
the bootloader, partition table and NVS. Esptool write verification and a
separate verify-flash pass both matched the built application. The subsequent
boot log remained in ROM download mode; normal application startup requires
a reset with BOOT released and is not yet confirmed.

Resolution of the reported Explorer stalls is **not verified**. After normal
startup, test repeated enable/open/eject, file hashes after reads/writes, and
recovery on both card capacities. Earlier hardware results below predate
these performance changes.

## Passed in this update

- **Code & security review** across six dimensions with adversarial verification; see
  `docs/CODE_REVIEW.md`. No critical/high issues, no memory-corruption or auth-bypass.
  Fixes applied for L-1 (credential scrubbing on all `change_pin` paths), L-2/L-3
  (desktop CLI robustness and download id-binding), L-4 (CDC RX backpressure) and S-1
  (NVS erase-retry on first boot). M-1 (default Wi-Fi PSK) addressed as a documentation
  warning. The fixed firmware rebuilds cleanly and the full host suite re-passes.
- **ESP32-S3 target build and link** with ESP-IDF **5.5.5**, GCC **14.2.0** (`esp-14.2.0_20260121`), regenerated configuration and exact dependency pins. The v1.0.0 application image is **1,525,968 bytes** (with PSRAM enabled), leaving about 64% of the 4 MiB application partition free. The final build log contains no compiler warnings or errors.
- Resolved components: esp_lvgl_port 2.9.0, esp_tinyusb 2.4.0, led_strip 3.1.0~1, TinyUSB 0.21.0~2, LVGL 9.6.0~1. `firmware/dependencies.lock` records the full resolution.
- Build configuration: ESP32-S3, 16 MB flash, custom partition table, FAT long filenames, one USB CDC interface with 1024-byte RX/TX buffers plus USB MSC with a 4096-byte transfer buffer. Secure Boot and flash encryption are not enabled.
- **17 Python regressions**, run under Windows and Linux: framing/CRC/stream recovery, complete chunks and maximum catalogs, malformed dimensions, empty/exact-block/multiblock file transfers, partial/stalled serial writes, ambiguous port detection, truncated downloads, destination/temporary-file preservation, missing commit acknowledgements, invalid filenames, 14-byte filename and hex-ID downloads.
- **Native firmware web/storage/config/runtime regressions** under WSL Ubuntu with GCC, OpenSSL/cJSON adapters, AddressSanitizer and UndefinedBehaviorSanitizer. Checks cover fragmented HTTP reads, browser sessions, settings validation/write failures, key preservation during failed credential changes, credential rotation, authenticated empty files/catalogs, malformed lengths, incomplete uploads, idle locking, Host/Origin rejection and unauthenticated trailing catalog bytes. The final run passed without sanitizer diagnostics. The adapters do not exercise mbedTLS or ESP32 drivers.
- Python bytecode compilation, CLI help entry point, and embedded JavaScript syntax validation with Node.js.
- A strict AES-GCM driver adapter tests the real `vault_crypto.c` wrapper with the ESP-IDF driver's requirement for non-null zero-byte buffers. It covers empty encryption/decryption, authentication failure propagation and invalid nonempty buffers. This contract test does not test cryptographic correctness. Web regressions cover short setup credentials and SD write failure reporting without incorrect-PIN messages or retry penalties.

## Physical board progress

- Inspected an ESP32-S3 revision 0.2 with 16 MB flash and 8 MB embedded PSRAM. Saved and verified a complete private flash backup before writes. The backup is excluded from the source package.
- Flashed the development firmware using esptool 5.6.0 with successful write-hash verification. User confirmed the screen and phone setup page run. USB CDC enumerates as COM4; real desktop status and locked-file-list rejection passed.
- The card initially failed to mount. A temporary disposable-card formatter was loaded, then normal firmware restored. Its serial write/read test output was not captured, so no formatter test pass is claimed. The phone now reaches setup rather than reporting unavailable storage.
- First-time setup exposed an empty-catalog AES-GCM incompatibility: the ESP-IDF accelerated driver rejects null buffers even for length zero. The corrected image was built and flashed with hash verification. User confirmed phone setup/unlock works.
- Physical USB-serial storage tests passed for **0, 1, 4095, 4096, 4097 and 65536 bytes**: upload, list metadata, download with matching SHA-256, delete, then lock and reject listing. Only generated uniquely named test files were used, and they were deleted. The device was left locked.
- The new native USB-drive feature passes sanitized block/MSC tests: FAT32 geometry, cross-block/cross-segment I/O, persistence across unlock and credential rotation, three journal interruption points, primary-header recovery, ciphertext/map/missing-segment rejection, capacity/range checks, medium-change signaling, eject and lock gating. An independent `fsck.fat -n` check validates a generated test volume.
- **Real Windows USB-drive bring-up now passes creation and mount.** On the physical board, after enabling the 8 MB octal PSRAM (see below), **Enable SD card drive** creates the encrypted volume and Windows mounts it as a FAT32 drive (label "ESP32 VAULT", ~57.8 GB from a ~60 GB card). Before the PSRAM fix, the drive-state allocation failed under internal-RAM pressure and the controller reported "USB drive could not be opened." Host read/write throughput, eject/remount and power-cycle persistence on Windows still warrant further exercise.
- **PSRAM fix:** the build now enables `CONFIG_SPIRAM` (octal, 80 MHz, added to the heap, `IGNORE_NOTFOUND`). The board boots cleanly with PSRAM active, confirming the octal mode. The USB-drive working set is allocated from PSRAM at runtime (internal-RAM fallback; capacity still measured from free space). Full `--clean-config` rebuild is clean; host suite re-passes.
- No eFuses were programmed. Secure Boot and flash encryption remain disabled.

## Reproduce

```sh
# Portable desktop checks (also works on Windows without native build packages)
python tests/run_checks.py --python-only

# Linux native regressions: GCC, OpenSSL headers, libcjson runtime/development package
python3 tests/run_checks.py

# Isolated Ubuntu/WSL target build; first run downloads official ESP-IDF/compiler
bash tools/build_wsl.sh --clean-config
```

The builder uses `/var/tmp/esp32-vault-toolchain` as a separate cache, preserving system ESP-IDF installations. It copies outputs to `artifacts/firmware` and never flashes. Build and host logs are included in the packaged artifacts. GitHub Actions has matching jobs, but no remote CI run is claimed.

## Verify the card is encrypted

`tools/verify_sd_encryption.py` checks a card **after** it has been removed from the
device. It never writes to the card.

1. Create a canary file and copy it onto the **ESP32 VAULT** drive (you can also
   upload it with the CDC tools):

   ```sh
   python tools/verify_sd_encryption.py make-canary
   ```

2. Safely eject ESP32 VAULT in the OS, lock the vault, unplug the device and remove
   the microSD card. Delete the local copy of the canary file.
3. Mount the card on a computer (read-only if possible) and run:

   ```sh
   python tools/verify_sd_encryption.py check /path/to/card --canary VAULTCANARY...
   # Also scan the raw device, including free/deleted space (Linux; needs root):
   sudo python3 tools/verify_sd_encryption.py check /path/to/card --canary VAULTCANARY... --raw /dev/sdX
   ```

`PASS` means the canary text and filename don't appear anywhere on the card in
UTF-8 or UTF-16LE, and every written vault record (USB drive blocks, allocation maps,
volume root, journal, catalog and CDC file chunks) has random-looking ciphertext.
Files outside `/vault` are reported because the vault doesn't protect them.

Visible by design: the file names `usb-NNNNN.enc` etc., file sizes and counts, which
blocks have been written, record IVs and tags, and the PBKDF2 salt and iteration
count in `vault.meta`. None of these reveal file contents or names.

The checker was validated on the host against a vault produced by the real
`vault_storage.c`/`vault_drive.c` code. That vault passed. Planting a plaintext block
in a segment and a canary file outside `/vault` both produced `FAIL`.

## Still requires physical hardware or review

- LCD orientation/partial-refresh behavior, backlight, RMT LED patterns and microSD/FAT32 capacity under load.
- Actual phone/browser interaction and desktop GUI rendering. Syntax and host checks are not a visual UI pass.
- Wi-Fi/USB concurrency and disconnect/reset handling, stack watermarks/minimum heap, long transfers and maximum catalogs on device.
- Power interruption during provisioning, catalog replacement, PIN changes and SD-full conditions.
- mbedTLS known-answer/runtime checks and hardware acceleration. Target compilation verifies API/link compatibility, not runtime cryptography.
- Device-bound key derivation, recovery wrappers, persistent retry limits, authenticated transport, nonce allocation policy, signed updates and production security review.

See HARDWARE_VALIDATION.md. The firmware remains a development build for disposable test data.
