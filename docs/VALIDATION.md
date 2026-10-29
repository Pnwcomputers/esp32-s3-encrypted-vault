# Validation results â€” 2026-10-19

## USB mount performance changes — 2026-10-29

The 64 GB device initially kept Explorer waiting during mount. Live CDC
instrumentation recorded 29,619 reads over approximately 124 seconds, zero
writes/errors, and a maximum transfer callback time of 23 ms. The read count
then settled and the user confirmed the drive opened. Read-only inspection
found 4 KiB clusters and two FATs of 60,570,112 bytes each, with clean-shutdown
and no-hard-error flags set. The workload is consistent with scanning both
FATs; individual request LBAs/byte totals were not recorded. Earlier Windows
disk event 51 messages alone do not establish an SD-card failure.

With user authorization, 23 files (33,031,963 bytes) were backed up and verified
with SHA-256 before Windows recreated only the virtual FAT32 volume using
32 KiB clusters. All files were restored with matching hashes. The physical
SD filesystem and encrypted container format were preserved. The new logical
geometry is 512-byte sectors, 64 sectors/cluster, 121,376,768 sectors, 3,142
reserved sectors and two FATs of 14,813 sectors (7,584,256 bytes each).

After safe eject and a user portal reconnect, reads settled at 3,761 in about
30 seconds, with zero device-reported errors and a maximum callback time of
24 ms. The user confirmed the drive opened. This reduces mount reads about
87% and the observed mount workload duration about fourfold. Mounting still
has a noticeable delay. Backup read throughput was about 471 KB/s; restore
write throughput about 302 KB/s, including Windows/encryption/journal work.
These are single-run observations, not controlled performance benchmarks.
exFAT remains a fallback plan. No 128 GB hardware test is claimed.

Firmware changes add 16 KiB encrypted-drive stdio buffers, FAT fast-seek
(default 256-word cluster-link maps), LCD updates outside the runtime gate,
slow-transfer/flush logging, and CDC command 02 GET_USB_DIAGNOSTICS. The
command reports counters and retained failure stages without file contents or
credentials. Diagnostic polling does not count as activity in the final source.
Newly created volumes >=4 GiB use 32 KiB clusters; existing geometry is retained
until the host filesystem is deliberately recreated after backup.

The pinned ESP-IDF 5.5.5/GCC 14.2.0 Windows build passes without compiler
warnings/errors. The diagnostic application (1,402,704 bytes) was flashed at
0x10000 and passed write verification plus a separate verify-flash digest check;
CDC diagnostics worked after reset into the application. A full 16 MB flash
backup was taken first. Bootloader, partition table and NVS were preserved.
The subsequent new-volume geometry/diagnostic-idle source changes also build
cleanly (1,402,720-byte application); that later image has not been flashed.

All 17 portable Python regressions pass. New native C assertions cover cluster
selection and retained I/O/authentication failure stages, but the Linux host C
suite was not run in this Windows environment. Independent validation of newly
synthesized 32 KiB-cluster volumes remains pending; the measured migration used
Windows formatting. Earlier build and hardware results below predate this work.

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
