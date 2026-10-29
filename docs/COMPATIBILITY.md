# Compatibility

## Device

| Board | Revision | Flash | PSRAM | Status |
|-------|----------|-------|-------|--------|
| Waveshare ESP32-S3-LCD-1.47 (no touch) | ESP32-S3 rev 0.2 | 16 MB | 8 MB octal | ✅ Development board; see [VALIDATION.md](VALIDATION.md) |

Other boards, including similarly named Waveshare models, are **not supported**. The
pin map in the [README](../README.md#-hardware--pinout) is specific to this board.
Current firmware requires PSRAM; a board without it cannot open the USB drive.

## Build environment

| Component | Version | Status |
|-----------|---------|--------|
| ESP-IDF | 5.5.5 | ✅ Clean build, no warnings |
| ESP-IDF | 6.x | ❌ Not supported for this snapshot |
| GCC (Xtensa) | 14.2.0 (`esp-14.2.0_20260121`) | ✅ |
| esp_tinyusb / TinyUSB | 2.4.0 / 0.21.0~2 | ✅ Pinned in `firmware/dependencies.lock` |
| esp_lvgl_port / LVGL | 2.9.0 / 9.6.0~1 | ✅ Pinned |
| led_strip | 3.1.0~1 | ✅ Pinned |
| Isolated build (`tools/build_wsl.sh`) | Ubuntu / WSL | ✅ |

## Host computers (USB)

| Host OS | USB drive (MSC) | USB CDC tools | Notes |
|---------|-----------------|---------------|-------|
| Windows | ✅ Create, mount (FAT32), read/write/delete | ✅ Status, upload/download/delete (0 B … 64 KiB) | Eject/remount and power-cycle persistence still need more testing |
| Linux | ⏳ Not yet tested on hardware | ⏳ Python checks pass; not tested on hardware | Native regressions run on Linux |
| macOS | ⏳ Not yet tested | ⏳ Not yet tested | |

## microSD cards

| Format | Status |
|--------|--------|
| FAT32 | ✅ Required. A ~60 GB card was tested. |
| exFAT / NTFS | ❌ Not mounted. The firmware never reformats a card; prepare FAT32 separately. |

## Desktop tools

Python 3.10+ with `pyserial` (CLI) and `PySide6` (GUI). Regression checks run on
Windows (`--python-only`) and Linux (full suite).

## Known issues

- USB drive writes are cached in RAM for up to ~1 s; **eject before unplugging** or
  the last writes can be lost. See [USB_DRIVE.md](USB_DRIVE.md#write-cache).
- Windows may need the USB cable reconnected after eject before **Reconnect SD card
  drive** shows the volume again.
- Drive capacity is fixed when the volume is created; it doesn't grow after old
  phone/client files are deleted.

Have a result for another host or card? Open an issue with the board revision, host
OS and card details.
