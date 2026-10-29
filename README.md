<p align="center">
  <img src="assets/esp32vaultlogo.jpg" alt="Self-Hosted, Offline Encrypted USB Storage for the Waveshare ESP32-S3-LCD-1.47." width="600"/>
</p>

# 🔐 ESP32-S3 Encrypted Vault Drive *via MicroSD Card*
## *Self-Hosted, Offline Encrypted USB Storage for the Waveshare ESP32-S3-LCD-1.47*

![Platform](https://img.shields.io/badge/Platform-ESP32--S3-E7352C)
![Framework](https://img.shields.io/badge/ESP--IDF-5.5.5-blue)
![UI](https://img.shields.io/badge/LVGL-9-blueviolet)
![Encryption](https://img.shields.io/badge/Encryption-AES--256--GCM-green)
![KDF](https://img.shields.io/badge/KDF-PBKDF2--HMAC--SHA256-green)
![Status](https://img.shields.io/badge/Status-Development%20Build-orange)
![GitHub issues](https://img.shields.io/github/issues/Pnwcomputers/esp32-s3-encrypted-drive)
![Maintenance](https://img.shields.io/badge/Maintained-Yes-green)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Release](https://img.shields.io/github/v/release/Pnwcomputers/esp32-s3-encrypted-drive)

### **A ~$100 +/- Encrypted USB Drive You Build Yourself: Using an ESP32-S3 and a microSD Card, Unlocked From a Local Web Portal!!**

Hardware-encrypted flash drives typically cost **$150–$250 for just 64 GB**. This project does the same basic job with about **~$100 +/- in parts**: a ~$25 ESP32-S3 USB stick and an ordinary microSD card of your choice. 
Need more space? 
Swap in a bigger card. 
The firmware is open source (MIT), so you can read exactly how your data is protected.

Development firmware for the [**Waveshare ESP32-S3-LCD-1.47**](https://a.co/d/0b47s5Qs) (specifically the USB-A thumb-drive form factor) that turns a plain microSD card into an encrypted vault. The card holds only AES-256-GCM ciphertext. The device hosts its own Wi-Fi access point and web portal; after you unlock there, the ESP32 exposes the decrypted volume to the host computer as a real USB drive, decrypting and encrypting every block on the fly. No router, no internet, no buttons, no touch input.

> ⚠️ **This is a development build for disposable test data.** The ESP-IDF 5.5.5 target build is clean, the host regression suite passes, and the encrypted USB drive has been verified creating, mounting (FAT32), reading and writing on real Windows. Device-bound keys, authenticated transport, Secure Boot/flash encryption and an independent security review are **not** done; see [Security Model & Limits](#️-security-model--limits).

---

## 💡 Why This Exists

Commercial encrypted USB drives work well, but they're expensive, their capacity is fixed when you buy them, and their firmware is closed. The goal here is an **inexpensive, open alternative** made from parts anyone can buy.

| | **This project** | Typical hardware-encrypted flash drive |
|---|---|---|
| **Cost Estimate(s)** | **~$25** ESP32-S3 LCD + microSD Card | ~$150 - $250 +/- |
| **Bigger capacity** | Buy a bigger microSD card | Buy a new, pricier drive |
| **Encryption** | AES-256-GCM, done on the ESP32 | AES-256 (usually XTS), done in the drive |
| **Unlock** | Phone/browser over the device's own Wi-Fi | Physical keypad on the drive |
| **Firmware** | Open source (MIT) and auditable | Closed |
| **Certification & tamper resistance** | None yet | Often FIPS 140-2/140-3 validated, epoxy-sealed, brute-force wipe |

<sub>Typical 64 GB street prices as of Oct 2026 for drives such as the Apricorn Aegis Secure Key 3NX, Kingston IronKey Keypad 200 and iStorage datAshur PRO2; prices vary by retailer. Board price from Waveshare's store.</sub>

**Be honest about the trade-off:** commercial drives carry certifications, physical tamper protection and years of review. This project doesn't yet. It's great for learning, tinkering and low-stakes privacy; for anything that truly matters, wait for the roadmap's security items (device-bound keys, persistent brute-force limits, Secure Boot) and an independent review.

---

## 📌 Project Status

| Area | State |
|------|-------|
| ESP-IDF 5.5.5 target build & link | ✅ Clean (no warnings) |
| Host regression suite (ASan/UBSan) | ✅ 17 Python + native firmware + encrypted-drive checks pass |
| Phone/web setup, unlock, credential rotation | ✅ Verified on hardware |
| Encrypted USB-serial (CDC) file round-trips | ✅ Verified on hardware (0 B … 64 KiB, SHA-256 match) |
| **Encrypted USB drive (MSC) on Windows** | ✅ Create + mount (FAT32) + read/write/delete verified |
| On-device durability: eject/remount, power-cycle, long transfers, max catalog | ⏳ Needs further exercise |
| Device-bound keys, HTTPS, Secure Boot, signed updates, security review | ❌ Deferred (see Roadmap) |

<details>
<summary>🐛 Recently fixed</summary>

| # | Area | Issue | Fix |
|---|------|-------|-----|
| 1 | `sdkconfig.defaults`, `vault_drive.c` | 8 MB PSRAM was disabled, so the whole stack (Wi-Fi + LVGL + TinyUSB + HTTP) competed for ~512 KB internal SRAM and the USB drive's ~32 KB working allocation failed; **Enable SD card drive** always reported *"USB drive could not be opened."* | Enabled octal PSRAM and allocate the drive state from it at runtime (internal fallback; nothing static). Drive now mounts in Windows as a 57.8 GB FAT32 volume. |
| 2 | `vault_web.c` (L-1) | Current & new credentials left un-zeroed on `change_pin` error paths. | Scrub credentials and request body on **every** exit path. |
| 3 | `cdc_protocol.c` (L-4) | Unchecked `xRingbufferSend` could silently drop received bytes under backpressure. | Apply brief backpressure and log overflow instead of a silent drop. |
| 4 | `main.c` (S-1) | `nvs_flash_init()` aborted boot on a blank/version-changed NVS. | Erase-once-and-retry so a fresh chip recovers. |
| 5 | `desktop/` (L-2, L-3) | CLI crashed on malformed device responses; download didn't bind the returned `file_id` to the request. | Graceful error handling + skip bad `ls` records; verify the device returned the requested file. |

A full multi-dimension code + security review is in [`docs/CODE_REVIEW.md`](docs/CODE_REVIEW.md).

</details>

---

## ✨ Key Features

- **🔐 Encrypted at rest**; AES-256-GCM protects every file chunk and the catalog; a random data key is wrapped with PBKDF2-HMAC-SHA256. A removed card is just ciphertext.
- **📶 Self-hosted unlock**; The device runs its own WPA2 SoftAP and embedded web portal at `http://192.168.4.1`. No router or internet required; app assets are baked into firmware.
- **💾 Real encrypted USB drive**; While unlocked, the microSD is exposed to the host as a FAT32 USB Mass Storage drive ("ESP32 VAULT"). The ESP32 decrypts on read and encrypts on write, block by block; the host never sees raw card sectors.
- **🔌 USB CDC file protocol + desktop tools**; A second interface offers a framed, CRC-checked file-transfer protocol with a Python CLI and GUI.
- **🖥️ LCD status + RGB LED**; ST7789 1.47″ LCD status screen (LVGL 9) and a GPIO38 WS2812 status LED (normal / dim / off).
- **🔒 Lock discipline**; Idle auto-lock, lock-on-eject, and credential rotation that rewraps the data key **without** rewriting file contents. Session keys are zeroed on lock.
- **🧱 Journaled writes**; Host writes are cached in RAM (up to 512 KB / ~1 s) and committed in batches through an authenticated redo journal (then segments, maps and root) with `fsync`, plus `.tmp`/`.bak` atomic replacement. **Eject before unplugging**, or the last cached writes can be lost.
- **🧪 Verifiable**; Host regression suite under AddressSanitizer/UBSan and a reproducible, isolated WSL target build.
- **🚫 No buttons or touch**; Everything is driven over Wi-Fi and USB.

## 🧩 How It Works

1. **Boot / pairing**; The device initializes the LCD, mounts the FAT32 microSD (never auto-formatting on failure), and brings up the `MyEarPods` SoftAP + web portal.
2. **Authenticate**; You connect to the AP and open `http://192.168.4.1`. First use creates a PIN/passphrase (6–63 UTF-8 bytes); later boots ask for it. Unlock derives the key that unwraps the random data key.
3. **Access**; Once unlocked, the vault is globally unlocked: press **Enable SD card drive** and the host sees the decrypted FAT32 volume. A browser session token (held only in the page) gates further web actions.
4. **Lock**; Safely eject in Windows, then lock (or let idle auto-lock fire). Keys and caches are wiped; the USB medium disappears.

## 🔌 Hardware & Pinout

Target: **Waveshare ESP32-S3-LCD-1.47** (no touch), 16 MB flash, 8 MB embedded octal PSRAM. **Confirm your exact board revision and schematic before flashing; do not apply these pins to another similarly named model.**

| Interface | Signal | GPIO |
|-----------|--------|------|
| **ST7789 LCD** | MOSI / SCLK / CS / DC / RST / BL | 45 / 40 / 42 / 41 / 39 / 48 |
| **microSD (SDMMC 4-bit)** | CLK / CMD / D0 / D1 / D2 / D3 | 14 / 15 / 16 / 18 / 17 / 21 |
| **RGB status LED (WS2812)** | DIN | 38 |

## 🚀 Getting Started

### Prerequisites

- 💻 [Waveshare ESP32-S3-LCD-1.47 USB-A Board](https://a.co/d/0372fDFW) (16 MB flash, 8 MB PSRAM)
- 💾 A [microSD card](https://a.co/d/02GP0tbx) (Start with disposable test data ONLY)
- 🧰 [ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/get-started/index.html) **5.5.5** (the manifest pins the verified framework and component versions)
- 🔌 USB-A connection + Host Computer
- 🧱 *Optional but Recommended* [3D Printed Enclosure](https://makerworld.com/en/models/1605019-case-for-waveshare-esp32-s3-1-47inch-with-keyring)

### Use the Device

1. **💾 Insert a FAT32 microSD and power the device over USB.** Failed SD mounts never auto-format the card.
2. **📶 Connect to `MyEarPods`**, password `53cur3ty` *(factory defaults; **change these in Device settings before trusting the device**; the default password is compiled into the firmware and identical on every un-reconfigured unit)*.
3. **🔓 Open `http://192.168.4.1`.** On first use, create and confirm a PIN or passphrase (6–63 UTF-8 bytes). On later boots, enter the existing credential.
4. **🟢 Press "Enable SD card drive"** once, then use **ESP32 VAULT** in File Explorer. It uses nearly all currently free microSD capacity; user files are never stored in ESP32 flash. **Safely eject in Windows before locking**; automatic locking waits while the drive is connected. See [USB drive behavior & limits](docs/USB_DRIVE.md).
5. **⚙️ Open Device settings** to change Wi-Fi name/password/channel, hidden SSID, idle lock, USB access, LED mode, screen brightness and rotation. Enter the current credential to save, then **Restart** from the page to apply network/USB/display changes.
6. **🔑 Change the PIN/passphrase** separately using the old credential plus confirmation. This rewraps the data key without rewriting file contents.

### Flash a Release (no toolchain needed)

Download the assets from the [latest release](https://github.com/Pnwcomputers/esp32-s3-encrypted-drive/releases/latest), check them with `sha256sum -c SHA256SUMS`, put the board in download mode (hold **BOOT** while plugging it in), then:

```sh
pip install esptool
esptool --chip esp32s3 --port YOUR_PORT write-flash \
  0x0 bootloader.bin 0x8000 partition-table.bin 0x10000 esp32_vault.bin
```

Unplug and replug to boot. Release images contain no settings, so the device starts with the factory Wi-Fi defaults; **change them right away**. Flashing doesn't touch the microSD card.

### Build & Flash

From an ESP-IDF 5.5.5 terminal:

```sh
cd firmware
idf.py set-target esp32s3
idf.py build
idf.py -p YOUR_PORT flash monitor
```

The defaults select 16 MB flash, the custom partition table, long FAT filenames, USB CDC + MSC, and the board's octal PSRAM. The committed lockfile pins `esp_tinyusb`, `esp_lvgl_port`, LVGL 9 and `led_strip`.

**Isolated / reproducible build (no system ESP-IDF needed):**

```sh
bash tools/build_wsl.sh            # downloads pinned ESP-IDF + compiler to /var/tmp on first run
bash tools/build_wsl.sh --clean-config   # verify the committed sdkconfig defaults
```

Outputs are copied to `artifacts/firmware/`. This helper builds **without** flashing.

### Desktop Tools (USB CDC)

From the repository root, install `desktop/requirements.txt`, then:

```sh
python -m desktop.vault_cli ports
python -m desktop.vault_cli status
python -m desktop.vault_cli ls
python -m desktop.vault_cli upload test.txt
python -m desktop.vault_cli download test.txt
python -m desktop.vault_cli lock
python -m desktop.vault_gui
```

Unlock through Wi-Fi before USB file operations. The CDC path is a **file-transfer protocol**, not a drive letter (that's the MSC drive above). It supports up to 256 records, 127 UTF-8 bytes per filename, and 4 GiB − 1 byte per file; practical transfers are smaller.

## 🧪 Verification

```sh
python tests/run_checks.py
# Windows without GCC/OpenSSL (desktop checks only):
python tests/run_checks.py --python-only
```

The runner executes 17 Python regression functions plus a C regression executable built from the actual firmware web/config/runtime/storage/drive code. The Linux host harness needs GCC, OpenSSL dev headers and libcjson; it substitutes host crypto/HTTP/NVS/FreeRTOS adapters (it does **not** exercise mbedTLS or ESP32 drivers). AddressSanitizer and UndefinedBehaviorSanitizer are enabled. In restricted environments where LeakSanitizer can't read `/proc`, run `ASAN_OPTIONS=detect_leaks=0 python tests/run_checks.py`.

To confirm a removed card holds only ciphertext, use `tools/verify_sd_encryption.py`. It plants a canary file through the vault, then scans the removed card for it. See [Verify the card is encrypted](docs/VALIDATION.md#verify-the-card-is-encrypted).

See [validation results](docs/VALIDATION.md) and the [remaining hardware checks](docs/HARDWARE_VALIDATION.md).

## 📚 Documentation

| Topic | Document |
|-------|----------|
| Installation & build | [`docs/INSTALLATION.md`](docs/INSTALLATION.md) |
| Device settings & HTTP API | [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) |
| Encrypted USB drive | [`docs/USB_DRIVE.md`](docs/USB_DRIVE.md) |
| USB CDC wire protocol | [`docs/PROTOCOL.md`](docs/PROTOCOL.md) |
| Status LED patterns | [`docs/STATUS_LED.md`](docs/STATUS_LED.md) |
| Setup & recovery | [`docs/PROVISIONING_AND_RECOVERY.md`](docs/PROVISIONING_AND_RECOVERY.md) |
| Security model & limits | [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) |
| Proposed key design (future) | [`docs/KEY_DESIGN.md`](docs/KEY_DESIGN.md) |
| Code & security review | [`docs/CODE_REVIEW.md`](docs/CODE_REVIEW.md) |
| Validation evidence | [`docs/VALIDATION.md`](docs/VALIDATION.md) |
| Hardware validation checklist | [`docs/HARDWARE_VALIDATION.md`](docs/HARDWARE_VALIDATION.md) |
| Compatibility | [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md) |
| Troubleshooting | [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) |
| FAQ | [`FAQ.md`](FAQ.md) |
| Changelog | [`Logs/CHANGELOG.md`](Logs/CHANGELOG.md) |

## 🗂️ Project Structure

```text
esp32-s3-encrypted-drive/
├── firmware/
│   ├── main/
│   │   ├── main.c                 # Boot, LCD/LVGL, SoftAP, task wiring
│   │   ├── vault_crypto.*         # AES-256-GCM + PBKDF2 wrappers
│   │   ├── vault_storage.*        # Catalog/index, key wrap, file chunks
│   │   ├── vault_drive.*          # Encrypted USB block device + redo journal
│   │   ├── vault_msc.*            # TinyUSB Mass Storage callbacks
│   │   ├── vault_web.*            # HTTP portal + REST API
│   │   ├── vault_index.html       # Embedded web UI
│   │   ├── cdc_protocol.*         # USB CDC file-transfer protocol
│   │   ├── vault_config.*         # NVS-backed settings
│   │   ├── vault_runtime.*        # Serialization gate + idle lock
│   │   └── status_led.*           # GPIO38 WS2812 status LED
│   ├── partitions.csv             # Custom 16 MB partition table
│   ├── sdkconfig.defaults         # Pinned build config (incl. PSRAM)
│   └── dependencies.lock          # Resolved component versions
├── desktop/                       # Python CLI + GUI + protocol
├── tests/                         # Python + native (ASan/UBSan) regressions
├── tools/build_wsl.sh             # Reproducible isolated target build
├── tools/verify_sd_encryption.py  # Check a removed card holds only ciphertext
├── docs/                          # Threat model, protocol, validation, etc.
│   └── archive/                   # Original design spec (historical)
├── Logs/CHANGELOG.md              # Release history
├── .github/                       # CI, issue/PR templates, contributing, security policy
└── artifacts/                     # Build outputs (gitignored)
```

## 🛡️ Security Model & Limits

**What it protects:** data at rest on a removed/copied card, and host access gated behind web unlock. **What it does not (yet):**

- 🔑 A short numeric PIN is vulnerable to **offline guessing from a copied card**; PBKDF2 is 10,000 rounds and there is **no device-bound eFuse secret** or recovery-key wrapper.
- 🌐 The controller uses **HTTP over WPA2, not HTTPS**. The factory Wi-Fi password (`53cur3ty`) is compiled into the firmware and identical across un-reconfigured devices; **change it before trusting the device.** Anyone with USB access can operate the vault while it is globally unlocked.
- 🕵️ Names and timestamps are encrypted in the catalog, but raw container headers, file counts, lengths, allocation and access patterns remain observable. Nonces are random 96-bit values, not a counter with a uniqueness guarantee.
- 🚦 Retry delays are RAM-only and reset on power cycle. Settings live in NVS **without flash encryption**. Secure Boot, flash encryption, signed updates, FIDO keys and credential recovery are **not** implemented.
- 🧱 File replacement uses checked writes, flush/sync and a recoverable backup-rename sequence; not a full filesystem journal or a guarantee against arbitrary SD corruption/power loss. There is **no anti-rollback** protection.

**No eFuses are programmed by this project.** Full details in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## 🔮 Roadmap: Reliability & Security

### 🧱 Reliability

- **⚡ USB write throughput**; Writes are now cached and committed in batches (previously ~13 KB/s, one journaled block at a time). Still to do: measure on hardware, and make the cache size/idle-commit delay configurable.
- **🧯 Power-loss hardening**; Move beyond backup-rename recovery toward a true transactional/journaled guarantee across arbitrary SD power loss, with stress tests around catalog, credential and volume-root replacement.
- **🔁 In-web volume recovery**; A deliberate "reset/recreate USB volume" action so a stale or undecryptable header can never dead-end the drive without pulling the card.
- **📏 Capacity reclaim/resize**; Grow or reclaim USB-drive capacity after deleting legacy files (currently fixed at creation time).
- **🧪 Expanded on-device validation**; Eject/remount and power-cycle persistence on Windows, maximum (256-entry) catalogs, multi-megabyte transfers, and stack-watermark/minimum-heap measurement under combined Wi-Fi + LCD + USB load.
- **🔌 Transport robustness**; Harden overlapping Wi-Fi/USB operations, USB disconnect mid-transfer, and idle-lock interactions with in-flight writes.

### 🔒 Security

- **🔑 Per-device Wi-Fi credentials**; Replace the shared factory PSK with a random per-device password shown on the LCD (or force a change during provisioning before the portal accepts unlock).
- **🧬 Device-bound key derivation**; Mix an eFuse-held device secret into the KDF so a copied card is not offline-guessable, and gate reads to the physical device.
- **🧮 Stronger / upgradable KDF**; Higher PBKDF2 cost or a memory-hard function (e.g. Argon2), with versioned on-card format migration.
- **🌐 Authenticated transport**; HTTPS/TLS (or an equivalent authenticated channel) for the portal instead of HTTP-over-WPA2, plus hardened session-token handling.
- **🚦 Persistent anti-brute-force**; Attempt counters and lockout that survive power cycles, not RAM-only backoff.
- **🧊 Platform hardening**; Secure Boot, flash encryption for NVS/settings, and signed OTA updates; enabled only after review and with documented recovery.
- **🔙 Anti-rollback**; Monotonic version/nonce counters to resist restoring an older valid card image, and a defined nonce-allocation policy.
- **🗝️ Recovery & 2FA**; An independent recovery-key wrapper and optional FIDO/WebAuthn security-key enrollment.
- **🕵️ Metadata minimization**; Reduce observable file counts/lengths/allocation patterns where feasible.
- **🔎 Independent security review**; A third-party audit before any non-disposable use.

## 🤝 Contributing

Contributions are welcome; see [`.github/CONTRIBUTING.md`](.github/CONTRIBUTING.md):

- **📖 Documentation**; Clarify the README/docs, expand the threat model, add validation evidence
- **🐛 Bug Reports**; Open an issue with hardware revision, logs, and reproduction steps
- **💡 Feature Requests**; Open an issue with a `[FEATURE]` tag and the use case
- **🔒 Security Issues**; Follow the [security policy](.github/SECURITY.md); please don't open public issues for vulnerabilities

## 📄 License

Released under the [MIT License](LICENSE.md). © 2026 Pacific Northwest Computers.

The software is provided "as is", without warranty. It is a development build: don't trust it with data you can't afford to lose.

## 📞 Support & Contact

- 📖 **Documentation**: this README and the [`docs/`](docs/) folder
- 🐛 **Bug Reports**: open an issue on GitHub
- 💡 **Feature Requests**: open an issue with a `[FEATURE]` tag
- 💬 **General Support**: [support@pnwcomputers.com](mailto:support@pnwcomputers.com)

---

## 📊 Statistics

![GitHub stars](https://img.shields.io/github/stars/Pnwcomputers/esp32-s3-encrypted-drive)
![GitHub forks](https://img.shields.io/github/forks/Pnwcomputers/esp32-s3-encrypted-drive)
![GitHub issues](https://img.shields.io/github/issues/Pnwcomputers/esp32-s3-encrypted-drive)
![GitHub last commit](https://img.shields.io/github/last-commit/Pnwcomputers/esp32-s3-encrypted-drive)

**🔐 Your files, encrypted on the card; unlocked only from your pocket, over a network no one else is on.**

Built with ❤️ for privacy, reliability, and hardware you control.

[⭐ Star this repo](https://github.com/Pnwcomputers/esp32-s3-encrypted-drive) if it's useful!

---

*Updated October 2026*
*Tested on the Waveshare ESP32-S3-LCD-1.47 (rev 0.2; 8 MB PSRAM, 16 MB flash). Development build; use disposable test data until hardware validation and a security review are complete.*
