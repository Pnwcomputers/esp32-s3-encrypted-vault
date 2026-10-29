# Current security model

The primary control surface is the device's persistent WPA2 SoftAP and HTTP page. There are no application buttons or touch inputs. Internet access is unnecessary; the local radio remains active while unlocked.

## Implemented boundaries

- A random AES-256 data key encrypts file chunks and the catalog with GCM. Chunk AAD binds file ID, chunk number and length. Download lengths and container dimensions are checked against the authenticated catalog.
- PBKDF2-HMAC-SHA256 with the existing 10,000-round format derives the key used to wrap the data key. Wrong credentials fail GCM authentication.
- Web protected endpoints require a random page session token. Settings and credential changes also require the existing credential. Unlock and credential failures incur a bounded RAM-only retry delay.
- USB file commands require the device's global unlocked state. There is no USB unlock command. HTTP operations, USB commands and automatic locking serialize storage access.
- USB Mass Storage exposes an encrypted SD-backed FAT32 volume only while unlocked. Authenticated roots/maps/blocks bind volume and address; a redo journal protects logical updates once committed; up to ~1 s of acknowledged writes live only in RAM until the next commit, so removal without eject can lose them. Legacy mutations are blocked while exported. Automatic locking waits until host eject; manual locking/settings changes also require eject. See USB_DRIVE.md.
- Locking erases the active data key and clears the in-memory catalog, closes transfers and removes the current upload temporary file. Browser status requests do not postpone idle locking.

## Limits and deferred goals

A copied SD card permits offline PIN/passphrase guessing: there is no hardware-held device secret in key derivation. A short numeric PIN is not offline-guess resistant. PBKDF2 cost strengthening and format migration remain future work.

HTTP does not provide end-to-end TLS protection. WPA2 protects the local link only within its trust assumptions, and that protection depends on the PSK being secret. **The factory default SSID (`MyEarPods`) and WPA2 password (`53cur3ty`) are compiled into the firmware and are identical on every device that has not been reconfigured; until you change the Wi-Fi password they provide no confidentiality, and anyone in radio range who knows the firmware can join the AP.** The unlock portal (`/`, `/api/status`, `/api/unlock`) is reachable to anyone associated to the AP — this is not a vault-auth bypass (the data key stays random and PIN-wrapped, and online unlock attempts are exponentially rate-limited up to ~32 s), but it exposes status metadata and the (throttled) online PIN-guessing surface. **Change the Wi-Fi password in Device settings before trusting the device.** A per-device random PSK (shown on the LCD) or a forced change at provisioning would remove this shared-secret weakness and is recommended before any production use. Browser session tokens are bearer secrets. The vault is globally unlocked for USB, so any connected host can use it while unlocked. An authorized/compromised browser or host can copy plaintext.

Filename and timestamp catalog fields are encrypted, but raw file container headers expose dimensions and identifiers. File counts, lengths, access patterns and storage allocation remain observable. Random 96-bit nonces have probabilistic collision risk; no persistent nonce counter is implemented.

NVS configuration is not protected by flash encryption in this build. Secure Boot, signed firmware updates, anti-rollback counters, persisted retry limits, independent recovery wrapping and FIDO security-key support are not implemented. No eFuses are modified.

Checked file writes and backup rename recovery improve interruption handling but do not guarantee transaction durability across all FAT/SD power failures. Card cloning, replay, deletion, physical probes, fault injection, side channels and malicious firmware are outside the current protection boundary. There has been no independent security audit.
