# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Dated sections before 1.0.0 record development history before the first release.

## [Unreleased]

## [1.1.0] - 2026-10-29

### Firmware
- New virtual volumes >=4 GiB use 32 KiB FAT32 clusters. On one 64 GB device,
  recreating the virtual filesystem reduced the observed mount workload from
  about 124 seconds / 29,619 reads to 30 seconds / 3,761 reads, with zero device
  errors. Existing volumes keep their geometry; back up files before conversion.
- Add 16 KiB encrypted-drive file buffers and enable FAT fast-seek for read-only
  backing files. Periodic LCD updates release the shared USB gate before drawing.
- Add slow-transfer/flush logging and `02 GET_USB_DIAGNOSTICS`, plus
  `tools/usb_diagnostics.py`, to retain the first failed transfer and distinguish
  map/data I/O, authentication and cache-flush failures. Polling is not activity.
- Embed application version 1.1.0; CDC status reports 0x0101 (major/minor).
- When the microSD card can't be used, the LCD, web portal and unlock error now say
  why: exFAT or NTFS card ("reformat it as FAT32"), no readable FAT32 filesystem,
  card not detected, or vault folders not creatable. `/api/status` gains an
  `sd_error` field (`null` when the card is ready).
- USB drive writes are cached in PSRAM (128 × 4 KB) and committed in batches under
  a single `VLTTXN3` redo journal, after ~1 s idle, on SYNCHRONIZE CACHE, eject,
  lock, or when the cache fills. Previously every 4 KB write was journaled and
  fsynced on its own (~13 KB/s). **Eject before unplugging**: up to ~1 s of
  acknowledged writes can be lost otherwise. Older `VLTTXN2` journals still replay.
- Reads keep the current segment file open instead of reopening it per block.
- The SD bus runs at 40 MHz, falling back to 20 MHz if the card won't start.
- Unlocking no longer exposes an existing USB drive automatically; press
  **Enable/Reconnect SD card drive**.

### Documentation
- Preserve the updated README description, hardware links and cost estimates.
- Record the backup, restore hash checks, measured mount improvement and
  outstanding limits in `docs/VALIDATION.md`. exFAT remains deferred.

### Compatibility and validation
- The encrypted on-card format and settings remain compatible with 1.0.0;
  older single-block VLTTXN2 journals are still supported.
- The release targets the Waveshare ESP32-S3-LCD-1.47 USB stick, 16 MB flash
  and 8 MB octal PSRAM, using ESP-IDF 5.5.5.
- This remains development firmware. Mounting is faster, not instantaneous;
  read/write throughput remains limited by full-speed USB, encryption and
  journaling. The 128 GB device has not been hardware-tested in this update.

## [1.0.0] - 2026-10-21

First tagged release. Still a **development build for disposable test data**; see
the security limits in the README and `docs/THREAT_MODEL.md`.

### Firmware
- Binaries come from the image running on the validated board (ESP32-S3 rev 0.2,
  16 MB flash, 8 MB PSRAM): `esp32_vault`, compiled 2026-10-20 09:46 with ESP-IDF
  5.5.5. They were cut from a full flash backup that `esptool verify-flash` checked
  against the chip, and the app's embedded SHA-256 validates. The firmware source
  hasn't changed since commit `1bcc1f6` (PSRAM fix), which matches this build. Over
  USB CDC, `GET_STATUS` reports firmware version `0x0100`.
- Release assets: `bootloader.bin` (0x0), `partition-table.bin` (0x8000),
  `esp32_vault.bin` (0x10000) and `SHA256SUMS`. The settings (NVS) partition is not
  included, so a flashed board starts with factory defaults.

### Added
- `tools/verify_sd_encryption.py`: checks a card removed from the device. It plants
  a canary file through the vault, then searches the removed card (and optionally
  the raw device) for it, checks every vault record's ciphertext entropy, and flags
  files outside `/vault`. Procedure in `docs/VALIDATION.md`.

### Documentation
- README cleanup: removed duplicated intro/warning paragraphs and stray merge-leftover
  headings, added a documentation index and MIT license section, and corrected the
  subtitle (the Wi-Fi portal stays up while unlocked, so the device is offline but
  not air-gapped).
- Replaced template placeholders with project content: `docs/COMPATIBILITY.md`
  (renamed to fix a misspelled filename), `docs/TROUBLESHOOTING.md`, the
  bug report and hardware issue templates, and the code-of-conduct contact.
- Added `.github/SECURITY.md` and pointed the issue-template security link at it.
- Removed the unrelated "workstation deployment" issue template (left over from another
  project) and tailored the PR template and CONTRIBUTING to this repo's test and
  changelog workflow.
- Moved the original design spec (`NOTES.md`) to `docs/archive/ORIGINAL_SPEC.md`
  with a note that it describes superseded behavior (fixed PIN, Wi-Fi teardown).
- Folded `PATCH_NOTES.md` into this changelog.
- Refreshed stale statements in `docs/INSTALLATION.md` and
  `docs/HARDWARE_VALIDATION.md` to match the validation record.

### Fixed (repository)
- Moved the issue-labeler config from `.github/workflows/labeler.yml` (where GitHub
  tried to parse it as a workflow) to `.github/labeler.yml`, the path the
  auto-label workflow already referenced.
- Removed the duplicated front matter in the implementation-question issue template.

## 2026-10-20: Code review fixes and PSRAM (pre-release)

### Security
- Scrub the current and proposed credentials (and the raw request body) on **every**
  `change_pin` exit path, not only on success; also scrub the credential copy held in
  the parsed settings JSON before freeing it (`vault_web.c`). (Review L-1)
- Strengthened documentation of the hard-coded default Wi-Fi PSK: it is embedded in
  firmware and identical across un-reconfigured devices, so it provides no
  confidentiality until changed. No behavior change. (Review M-1; see
  `docs/THREAT_MODEL.md`, `docs/CODE_REVIEW.md`)

### Fixed
- **Enabled the board's 8 MB octal PSRAM** (`sdkconfig.defaults`) and allocate the USB
  drive's ~32 KB working set from it (`vault_drive.c`, runtime `heap_caps_calloc`, with
  an internal fallback; nothing static). Previously PSRAM was off, so the whole stack
  (Wi-Fi + LCD + USB + HTTP) competed for ~512 KB internal SRAM and the drive-state
  allocation failed under pressure, making **Enable SD card drive** always report
  "USB drive could not be opened." Confirmed fixed on hardware: the volume now mounts
  in Windows as a FAT32 drive ("ESP32 VAULT", ~57.8 GB). The drive capacity is still
  measured dynamically from the card's free space.
- CDC RX path now applies brief backpressure and logs an overflow instead of silently
  dropping received bytes when the worker falls behind (`cdc_protocol.c`). (Review L-4)
- `nvs_flash_init()` recovers from a blank/unformatted or version-changed NVS
  (erase-once-and-retry) instead of aborting the boot (`main.c`). (Review S-1)
- Desktop CLI reports malformed device responses cleanly instead of crashing with a
  traceback, and `ls` skips a single bad record instead of aborting the whole listing
  (`desktop/protocol.py`, `desktop/vault_cli.py`). (Review L-2)
- Desktop download verifies the device-returned `file_id` matches the requested file
  before writing, guarding against a firmware bug or session mix-up
  (`desktop/vault_client.py`). (Review L-3)

### Added
- `docs/CODE_REVIEW.md`: a full correctness + security review of the firmware and
  desktop tools (find → adversarial verify → synthesize), with findings and fixes.
- `LICENSE.md` (MIT).

## 2026-10-19: Encrypted USB drive and hardening

### Added
- Firmware split into modules (`vault_crypto`, `vault_storage`, `vault_web`,
  `vault_config`, `vault_runtime`, `cdc_protocol`, ...). AES-256-GCM chunk storage and
  encrypted catalog with a random data key wrapped by PBKDF2-HMAC-SHA256.
- First-use provisioning and PIN/passphrase unlock (replacing the fixed prototype
  PIN), browser session tokens, bounded RAM-only retry delays, NVS-backed settings,
  idle locking and credential rotation that preserves the data key. The SoftAP portal
  stays up while unlocked.
- Composite CDC + USB Mass Storage interface backed by AES-256-GCM encrypted data on
  the microSD, exposed only while unlocked and sized to nearly all free card capacity.
  Authenticated lazy block allocation, segmented backing files, a durable redo
  journal, FAT32 geometry, locked-medium gating, safe-eject handling and phone
  create/reconnect controls. See `docs/USB_DRIVE.md`.
- Non-blocking WS2812 RGB status LED controller for the onboard LED (GPIO38), wired to
  locked / PIN-entry / auth success+failure / unlocked / transfer / recovery states.
- Reproducible isolated WSL target build (`tools/build_wsl.sh`) with pinned ESP-IDF
  5.5.5, a regenerated component lockfile and exact component pins.
- Browser Host/Origin validation; storage usage hidden from unauthenticated status
  requests. Catalog/container trailing-byte checks and transfer ID validation.
- CI: Python, sanitized native host checks and an ESP32-S3 target build (replacing an
  unrelated Pester job). Python regressions expanded to 17 checks with a
  Windows-friendly `--python-only` mode; native browser-origin and trailing-catalog
  corruption checks added.

### Fixed
- First-time provisioning on ESP-IDF's accelerated AES-GCM path: provide non-null
  buffers for zero-byte catalog/file messages while keeping zero plaintext length.
  Added a strict driver-contract regression, and the web page now distinguishes
  setup/storage failures from incorrect credentials.
- TinyUSB 2.4.0 target-build error: removed the obsolete `rx_unread_buf_sz`
  initializer; CDC buffers are configured through sdkconfig defaults.
- CDC command-length checks, bounded TX backpressure waits, and shutdown now waits for
  the CDC worker before freeing its receive ringbuffer.
- NVS configuration is preserved on startup errors; display allocation is checked;
  the GUI no longer closes while a transfer worker is still running.

### Changed
- Hardened desktop client: partial serial writes, serialized command exchanges,
  monotonic timeouts, required acknowledgements, unique temporary downloads, fsync plus
  atomic replacement, and download cleanup. Ambiguous or unrelated ports require
  explicit selection.
- Filename downloads resolve to file IDs (including the ambiguous 14-byte legacy
  case); hex-ID downloads are retained. Path/control-character names are rejected.
  Existing destination and `.part` files are protected on failed downloads.
- Protocol documentation updated to describe the implemented wire format.

## 2026-10-13: Initial prototype

- Single-file prototype (`main.c`): ST7789 LCD via LVGL 9 (34-px column gap, full
  refresh), SDMMC microSD mount, a `MyEarPods` SoftAP with a fixed-PIN unlock page, and
  TinyUSB CDC after unlock. Superseded by the 2026-10-19 rework.
- Original design notes (now `docs/archive/ORIGINAL_SPEC.md`), desktop protocol
  skeleton and initial docs.
