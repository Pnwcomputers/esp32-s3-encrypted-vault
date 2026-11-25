# Physical-board validation still required

Target: Waveshare ESP32-S3-LCD-1.47, without touch input. Retained source pins: LCD MOSI45/SCLK40/CS42/DC41/RST39/backlight48; SD CLK14/CMD15/D0=16/D1=18/D2=17/D3=21; RGB LED38. Verify the exact board revision and schematic. No navigation-button wiring is required.

1. Build in ESP-IDF 5.5.5, resolve managed components and review warnings. Confirm 16 MB flash, the custom partition table, FAT long filenames, USB CDC and LVGL 9. Keep eFuse/security provisioning disabled.
2. With expendable FAT32 test media, verify SD mounting and locked startup. Remove the card and verify that the controller stays accessible and reports an unavailable card without formatting anything.
3. Connect via SoftAP, create a credential, lock, unlock with correct/wrong credentials and power-cycle. Verify Wi-Fi remains available throughout. Verify no hard-coded vault PIN works as a bypass.
4. Test mobile setup, typed passphrases and the virtual numeric keypad. Test retry delays, refresh/re-authentication and a second browser lacking a token.
5. Test files of 0, 1, 4095, 4096, 4097 and several megabytes using both transports. Compare SHA-256 of originals and downloads. Verify quoted/Unicode names, listing, deletion and a 256-entry catalog.
6. Test overlapping Wi-Fi/USB requests, USB disconnect during upload, HTTP interruption and idle lock between USB chunks. Verify no competing operation closes or corrupts an active storage handle. Long HTTP transfers serialize other operations until completion.
7. Save all settings. Reboot and verify Wi-Fi name/password/channel/hidden state, USB disabled/enabled, LED normal/dim/off, display brightness and rotations. Confirm saved credentials before changing connectivity settings.
8. Test LCD status and transfer callbacks; check RGB patterns against docs/STATUS_LED.md. Test wrong PIN while already unlocked and verify existing files still decrypt.
9. On copied test media, corrupt a tag/container length/catalog and verify decryption fails closed. Try incomplete uploads and ensure commit refuses them.
10. Test power interruption around catalog and credential replacement, including recovery from `.bak` files. Preserve card copies before tests. Check stack watermarks and minimum heap under combined Wi-Fi/LCD/USB load.

Host tests do not replace these checks. Steps 1–2 and parts of 3 and 5 have passed on a rev 0.2 board (setup/unlock; CDC transfers of 0 B–64 KiB; the USB drive creates and mounts on Windows); see VALIDATION.md for the evidence. The rest are still open.

## Android Bluetooth & USB write protection

Use a provisioned test card with a disposable USB image. Build with the fresh
`sdkconfig.defaults` so LE Secure Connections and Wi-Fi coexistence are enabled.

1. On Android 16 QPR2 or later, disconnect from the vault Wi-Fi. Scan, choose
   the board, enter its LCD pairing code in Android's prompt and confirm it in
   the app. Reject an incorrect code and confirm the PIN entry stays disabled.
2. Try a wrong vault PIN on BLE, then immediately try it over Wi-Fi. Confirm
   the shared backoff. Test a 63-byte UTF-8 credential and a bonded reconnect
   after reboot. Verify USB-disabled, unprovisioned and missing-image states.
3. Unlock with write protection. Read and hash a file, then verify write,
   delete and format attempts are denied on the expendable volume. After
   host media reload, verify write protection still applies. Eject and lock,
   then authenticate through the web UI without exporting. Verify a host
   media-start command cannot reload the previous export.
4. Confirm an app request to switch a mounted read-only export to read/write
   is refused. Eject, re-export read/write, write a disposable file, safely
   eject, power-cycle and verify its hash. Repeat the mount and throughput
   measurements in [USB drive performance](USB_DRIVE.md#compare-on-the-board).

See the [certification and tamper-resistance roadmap](CERTIFICATION_AND_TAMPER_RESISTANCE.md) for production design and evaluation criteria.
