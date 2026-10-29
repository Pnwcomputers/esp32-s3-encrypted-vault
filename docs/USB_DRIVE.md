# SD card access from the USB host

The microSD card supplies the storage. The ESP32 supplies USB Mass Storage,
credential checks and encryption; user files are not stored in its internal flash.
USB CDC remains available as a second interface for status/legacy tooling.

## Use

1. Unlock through the phone page at `http://192.168.4.1`.
2. On first use, press **Enable SD card drive**. This creates a FAT32 volume
   using approximately 97% of the card's currently free space. The difference
   covers authenticated block records, allocation maps, filesystem overhead and
   working space. Existing phone/client files are preserved. No physical SD
   reformat is performed. The volume has a 2 TiB implementation ceiling.
3. Open **ESP32 VAULT** in File Explorer and use normal file/folder operations.
   The host sees plaintext while unlocked; the SD backing files are encrypted.
   FAT32 limits an individual file to less than 4 GiB.
4. Right-click the drive in Windows and choose **Eject**, then lock through the
   phone page. Automatic locking waits while the USB drive is exported, because
   Windows can retain filesystem writes in its cache. Read/write activity also
   counts as activity. Eject resumes the configured idle-lock behavior.
5. Unlocking never exposes the drive by itself: press **Enable SD card drive**
   (or **Reconnect SD card drive** for an existing volume) each time. Until then
   the host sees no medium. Windows may require reconnecting the USB cable if it
   removed the entire USB device.

While locked the MSC device reports no medium and rejects block reads/writes.
It does not expose ciphertext as a mountable disk. Never accept a Windows format
prompt as a troubleshooting shortcut; it would replace the logical filesystem.

The older phone/desktop file area is separate. After eject, existing files can
be downloaded/deleted there. Once USB-drive capacity is assigned, new uploads to
that older area are disabled so they cannot consume capacity promised to the
host. Add new files through File Explorer. The physical SD backing filesystem
must not be modified externally.

## Storage layout

`/sdcard/vault/usb-drive.hdr` contains an authenticated encrypted volume root:
geometry and a bitmap of created backing segments. The FAT32 filesystem is a
logical block device; its initial boot sectors, FATs and root directory are
synthesized until written. Each segment covers 64 MiB of logical space and uses
`usb-NNNNN.enc` on the SD card. Segment files remain below FAT32's file-size
limit. Blocks and segment allocation maps use AES-256-GCM with fresh random
96-bit IVs and 128-bit tags. AAD binds volume UUID, segment and block number;
the allocation map has a separate reserved block identity.

Authenticated allocation maps distinguish an untouched block from a missing or
corrupted stored block. Untouched blocks return the initial FAT32 contents;
missing or corrupt allocated data returns an I/O error and closes the medium.
Session keys, decrypted roots/maps and the plaintext caches are erased on
locking/eject. Credential rotation keeps the same data key, preserving drive
contents.

### Write cache

Host writes land in a RAM write cache (128 × 4 KB blocks in PSRAM) and are
acknowledged immediately. The cache is committed to the card when:

- the host has not written for ~1 second,
- the host sends SYNCHRONIZE CACHE or ejects the drive,
- the vault is locked, or
- the cache is full (that write waits for the commit).

**Up to ~1 second of writes (at most 512 KB) are held in RAM before they reach the card. Pulling the stick (which also cuts its power) without ejecting can lose
those writes**, the same as yanking an ordinary flash drive mid-copy. Always use
**Eject** first. Data that was committed is never affected.

### Journal

Each commit first writes one authenticated redo transaction (`VLTTXN3`) to
`usb-drive.txn` covering every cached block plus the updated allocation maps
and volume root, fsyncs it, then updates the segment files (and the root only
when a new segment was created), then removes the journal. A complete journal
replays on the next unlock, including after an interrupted primary-header
update. Single-block `VLTTXN2` journals left by older firmware still replay.
Incomplete transaction `.tmp` files are not replayed. Corrupt committed
transactions fail closed. No automatic reformat occurs on any read/auth error.

This improves logical write recovery; it does not guarantee the physical SD's
FAT metadata or controller behavior across arbitrary power loss. The format has
no anti-replay counter. Restoring an older valid card image can restore older
data. Capacity is calculated at creation, not expanded automatically after
deleting old phone/client files. Speed is still lower than a native SD reader
because every block is encrypted and each commit is journaled.

Drive files use 16 KiB stdio buffers to avoid splitting encrypted records into
small SD operations. Firmware defaults enable FAT fast-seek for read-only
backing files, with a 1 KiB cluster-link map per open file. Existing build
configurations must enable `CONFIG_FATFS_USE_FASTSEEK=y` and set
`CONFIG_FATFS_FAST_SEEK_BUFFER_SIZE=256` to pick up these defaults. The periodic
LCD update releases the runtime gate before waiting for the display.
USB reads/writes and explicit/idle cache flushes taking at least 250 ms log `Slow USB`
with the LBA, size and elapsed time (including waiting for the runtime gate).
Capture these logs while enabling the drive and opening it in Explorer when
investigating mount stalls. Flush messages report elapsed time and result;
they do not include time waiting for the runtime gate. These messages contain
no file contents or keys.
Backing segment files are not sparse on FAT: a write beyond their current end
can require allocating a large gap, so buffering alone does not eliminate every
first-write or mount-time pause. Hardware timing still needs verification.

## USB integration

The pinned esp_tinyusb 2.4.0 descriptors provide CDC + MSC. Its default physical
storage adapter is deliberately excluded in the application CMake file, and
`vault_msc.c` supplies the callbacks/ownership hooks. Configuration fails if
the expected pinned component source layout changes. The physical SD remains
mounted only inside the application; MSC never receives raw physical SD sectors.
All web, CDC, MSC and idle-lock operations share the runtime gate. Legacy file
operations, settings changes, restart and manual locking are blocked until USB
eject. Status polling and SCSI readiness polling do not extend an idle session.

The drive remains a development feature until real Windows create/read/write,
eject, unlock/remount and power-cycle tests have passed. See VALIDATION.md for
the current evidence.
