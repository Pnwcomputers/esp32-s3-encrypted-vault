# ❓ Frequently Asked Questions

### 🔓 How do I unlock it without buttons or a touchscreen?
Connect to the device's Wi-Fi (`MyEarPods`) and open `http://192.168.4.1`. The LCD shows status only — the browser provides the keypad, passphrase entry, file manager and settings.

### 📶 Does Wi-Fi turn off after unlocking?
No. The SoftAP and HTTP portal stay available while powered, including while locked. This is **not** a radio-disabled air-gap design.

### 💾 Does it appear as a USB drive letter?
**Yes — once unlocked.** After you unlock through the web portal and press **Enable SD card drive**, the ESP32 exposes the decrypted volume to the host as a FAT32 USB drive labeled **ESP32 VAULT** (e.g. drive `D:` on Windows). There is also a separate **USB CDC file-transfer protocol** (the Python CLI/GUI) for the older phone/client file area. Both require the vault to be unlocked over Wi-Fi first; while locked, the drive reports no medium.

### 🐢 Why is writing to the drive slow?
Every 4 KB block is encrypted, and writes are committed to the card through a durable redo journal. Writes are cached in RAM and committed in batches (after ~1 s idle, on eject or lock), so throughput is much better than one block at a time, but still below a native card reader. **Eject before unplugging**, or the last second of writes can be lost. See [USB drive behavior](docs/USB_DRIVE.md#write-cache).

### 🧩 "Enable SD card drive" says *"USB drive could not be opened."* What now?
Make sure the vault is **unlocked**, USB access is enabled in Device settings, and the card has at least ~66 MB free (the FAT32 volume is built from free space at creation). Current firmware requires the board's **PSRAM** to be enabled — if you built older firmware with PSRAM off, the drive allocation fails; rebuild from this repo. The device never auto-formats the card.

### 🔑 Can I use a security key?
Not yet. The credential is a PIN or passphrase (6–63 UTF-8 bytes). FIDO/WebAuthn hardware keys and recovery-key enrollment are on the [roadmap](README.md#-roadmap-reliability--security), not implemented.

### 🧯 What if I forget the credential?
There is **no recovery wrapper** — the data key is unrecoverable without the PIN/passphrase. Resetting Wi-Fi settings does not recover encrypted files. Keep backups and preserve the original card before experimenting.

### 🕵️ If someone steals the card, can they read my files?
A removed card holds only AES-256-GCM ciphertext, so files are not directly readable. **But** a short numeric PIN is vulnerable to **offline guessing from a copied card** (there is no device-bound hardware secret yet), and the factory Wi-Fi password is public until you change it. Use a long passphrase and change the Wi-Fi password. See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

### 🛡️ Is the firmware ready for sensitive data?
**No.** This is a development build. No production security hardening (device-bound keys, HTTPS, Secure Boot/flash encryption, signed updates) or independent security review is done, and on-device durability testing is ongoing. Use disposable test data. See [`README.md`](README.md) and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

### 📇 Why won't my 64 GB card mount?
The firmware expects **FAT32**. Cards sold preformatted as exFAT need a FAT32 partition prepared separately (large cards often default to exFAT). The firmware never formats a failed mount; instead the LCD and web portal tell you the card is exFAT (or NTFS, or unreadable) and to reformat it as FAT32. See [Troubleshooting](docs/TROUBLESHOOTING.md#sd-card-unavailable--card-not-detected).
