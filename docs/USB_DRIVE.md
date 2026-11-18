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
   Newly created volumes of at least 4 GiB use 32 KiB clusters to reduce FAT
   size and Windows mount-time reads. Older volumes keep their stored geometry;
   updating firmware does not convert an existing 4 KiB-cluster volume.
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

## Read-only mode (write block)

Tick **Read-only (write block)** before pressing **Enable/Reconnect SD card
drive** to give the computer read access only. To make it the default, turn on
**Write-block the SD card drive by default** in Device settings. The tick box on
the drive card still decides each connection. The firmware then:

- reports the medium as write-protected (MODE SENSE), so Windows mounts it
  read-only and refuses to create, change, rename or delete files;
- rejects every WRITE command with DATA PROTECT before it reaches the write
  cache. Refused writes are not counted as device errors;
- keeps the write block if the host ejects and reloads the medium.

The mode can't change while the drive is connected. Eject it in Windows, then
reconnect with the other setting. Read-only applies to the USB drive only. If
an earlier session left a committed journal (for example, power was lost during
a write), opening the drive still replays it so the volume is consistent. That
only completes writes made before; it never adds new host data. The setting is
stored with the other device settings. Settings saved by older firmware load
with the write block off, and firmware older than this change ignores the
newer saved settings and uses its defaults.

`POST /api/usb/connect` accepts an optional body `{"read_only": true}`; without
one it uses the saved default. `/api/status` reports `usb_drive_read_only`.

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

### SD I/O path

The ESP32-S3 SD host cannot DMA to or from PSRAM. ESP-IDF therefore splits any
SD transfer whose buffer is in PSRAM into one 512-byte command per sector. The
drive's caches live in PSRAM, so every SD read and write goes through one
internal, DMA-capable staging buffer (32 KiB, falling back to 16 or 8 KiB if
internal RAM is short; the boot log reports the size). Writes are issued in
sector-aligned chunks, so FatFs moves whole sectors with multi-sector commands:

- the journal and root are written sequentially in full staging-buffer chunks;
- segment updates write each run of consecutive records (a map and/or adjacent
  blocks) as one span, not record by record;
- sequential reads of written blocks fetch up to seven consecutive records in one
  SD read (read-ahead). Staged records are discarded whenever the backing files
  change. Whole-block reads decrypt straight into the USB buffer.

The drive keys one AES-GCM context per session instead of re-keying for every
block. A new segment file is extended to its full size (about 64.4 MiB) the first
time it is written, while free card space is still contiguous. Before this,
segment files grew one flush at a time between journal files and could split
into more fragments than FAT fast-seek can map. Existing segment files keep
their current layout. Unwritten record slots in a preallocated segment hold
whatever the card had there before (often zeros); the authenticated map never
treats them as data.

Firmware defaults enable FAT fast-seek for read-only backing files, a 240 MHz
CPU clock (GHASH runs in software on this chip) and an 8 KiB TinyUSB MSC buffer
(two blocks per USB callback). `sdkconfig.defaults` only applies to options an
existing `firmware/sdkconfig` does not already set. To pick up these defaults,
delete `firmware/sdkconfig` and rebuild, or set `CONFIG_FATFS_USE_FASTSEEK=y`,
`CONFIG_FATFS_FAST_SEEK_BUFFER_SIZE=256`, `CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ_240=y`
and `CONFIG_TINYUSB_MSC_BUFSIZE=8192` in menuconfig. The periodic
LCD update releases the runtime gate before waiting for the display.
USB reads/writes and explicit/idle cache flushes taking at least 250 ms log `Slow USB`
with the LBA, size and elapsed time (including waiting for the runtime gate).
Capture these logs while enabling the drive and opening it in Explorer when
investigating mount stalls. Flush messages report elapsed time and result;
they do not include time waiting for the runtime gate. These messages contain
no file contents or keys.

The CDC command `02 GET_USB_DIAGNOSTICS` also returns transfer/error counters,
the first failing transfer's LBA, size and result, maximum transfer time, and
the retained storage failure stage (`map_io`, `map_auth`, `data_io`,
`data_auth`, `flush` or `cache_full_flush`). It is available while locked and
while the drive is exported. It cannot respond while the shared runtime gate
or USB task is blocked, and counters reset on device restart. Collect before
resetting when possible:

```sh
python tools/usb_diagnostics.py --port COM14 --seconds 60
```

The first write to a new 64 MiB segment allocates that whole file once, a short
pause on top of the flush. Throughput after these changes has not yet been
measured on hardware. Record new timings in VALIDATION.md.

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
