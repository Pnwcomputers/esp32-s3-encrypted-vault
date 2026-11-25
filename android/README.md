# ESP32 Vault for Android

Pair with the Waveshare vault using the one-time Bluetooth code on its LCD.
Then enter the vault PIN and select **Unlock and mount USB**. The app defaults
to write protection. Clear the checkbox only when you want the computer to
write to the drive. Safely eject on the computer before changing modes.

The board must already have a provisioned vault and a USB drive image created
in the web interface. Keep it plugged into the computer's USB data port. The
phone uses Bluetooth for unlock and export control. File transfers use USB
Mass Storage on the computer. The web interface remains available for setup
and management.

## Build

Open this `android` directory in Android Studio with JDK 17, Gradle 8.13 and
Android SDK Platform 36.1 installed. Use **Run** to install on a test phone, or
run `gradle :app:assembleDebug` from this directory.

The phone needs Android 16 QPR2 (API 36.1) or later. The app checks the operating
system's active LE encryption status before enabling the PIN field and again
before writing the PIN. The Bluetooth pairing prompt is separate from the
vault PIN. Enter the pairing code only when it appears on the intended board's
LCD. Nearby devices permission is required.

## Firmware Interface

| Attribute | UUID suffix | Operation |
| --- | --- | --- |
| Service | `399c1000` | Advertised service |
| Unlock command | `399c1001` | Write with response, one mode byte followed by 1–63 UTF-8 PIN bytes |
| Result | `399c1002` | Read one status byte |

Full UUID form is `399c100N-bc55-482d-a8a2-5fe1776146a1`. Mode `0` requests
read/write, and `1` requests read-only. The app requires an ATT MTU of at least
67 bytes. Status codes 0 through 7 mean idle, pending, exported, incorrect PIN,
retry later, image missing, storage/export error, and eject before changing
mode. Key derivation and media preparation run off the BLE host task. Exported
means the firmware is serving the USB image. The computer then mounts it on
its own schedule.

The firmware requires authenticated LE Secure Connections and a 16-byte link
key. The web and BLE controllers share one PIN backoff budget. First pairing
requires access to the LCD, and bonds are stored in the board's NVS. The vault
still requires its PIN for every app unlock. The app clears its credential
entry after sending and does not save it to disk.
