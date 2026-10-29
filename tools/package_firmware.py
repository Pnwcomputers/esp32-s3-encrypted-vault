"""Package a pinned ESP32-S3 build for a GitHub firmware release."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--commit', required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    version = re.search(r'set\(PROJECT_VER "([0-9]+\.[0-9]+\.[0-9]+)"\)',
                        (root / 'firmware/CMakeLists.txt').read_text()).group(1)
    if not re.fullmatch(r'[0-9a-f]{40}', args.commit):
        parser.error('--commit must be a full Git commit SHA')
    app = (args.build_dir / 'esp32_vault.bin').read_bytes()
    assert app[0] == 0xe9 and struct.unpack_from('<I', app, 32)[0] == 0xabcd5432
    assert app[48:80].split(b'\0')[0].decode() == version, 'Image version mismatch'
    assert app[80:112].split(b'\0')[0] == b'esp32_vault', 'Unexpected application'
    idf = app[144:176].split(b'\0')[0].decode()
    assert idf.startswith('v5.5.5'), 'Unexpected ESP-IDF version'
    config = (args.build_dir / 'config/sdkconfig.h').read_text()
    for required in ('CONFIG_IDF_TARGET_ESP32S3 1', 'CONFIG_SPIRAM_MODE_OCT 1',
                     'CONFIG_ESPTOOLPY_FLASHSIZE_16MB 1', 'CONFIG_FATFS_USE_FASTSEEK 1'):
        assert required in config, f'Missing build configuration: {required}'
    args.output.mkdir(parents=True, exist_ok=False)
    for name, source in {
        'esp32_vault.bin': 'esp32_vault.bin',
        'bootloader.bin': 'bootloader/bootloader.bin',
        'partition-table.bin': 'partition_table/partition-table.bin',
    }.items():
        shutil.copyfile(args.build_dir / source, args.output / name)
    info = dict(version=version, source_commit=args.commit, esp_idf=idf,
                target='esp32s3', flash_bytes=16 * 1024 * 1024,
                psram='8 MB octal', application_bytes=len(app),
                offsets={'bootloader.bin': '0x0', 'partition-table.bin': '0x8000',
                         'esp32_vault.bin': '0x10000'})
    (args.output / 'build-info.json').write_text(json.dumps(info, indent=2) + '\n')
    (args.output / 'FLASHING.md').write_text(f'''# ESP32 Vault v{version}

For the Waveshare ESP32-S3-LCD-1.47 USB stick with 16 MB flash and 8 MB octal PSRAM.
Source commit: {args.commit}. ESP-IDF: {idf}.

## Prepare

Safely eject the virtual drive first. Hold BOOT, tap RESET, then release BOOT.
Find the board's download-mode port (it can differ from the normal CDC port).
Replace COMx below with that port; Linux/macOS users use the appropriate device path.

```sh
python -m pip install esptool
```

## Update an existing vault

From this package directory, write only the application. These commands preserve
the existing bootloader, partition table, NVS settings and SD-card contents.

```sh
python -m esptool --chip esp32s3 --port COMx --baud 460800 write-flash 0x10000 esp32_vault.bin
python -m esptool --chip esp32s3 --port COMx verify-flash 0x10000 esp32_vault.bin
```

## Fresh installation

```sh
python -m esptool --chip esp32s3 --port COMx --baud 460800 write-flash --flash-mode dio --flash-size 16MB --flash-freq 80m 0x0 bootloader.bin 0x8000 partition-table.bin 0x10000 esp32_vault.bin
```

No erase-flash step is needed. These images contain no NVS/settings partition.
After flashing, release BOOT and tap RESET if the board stays in download mode.
Unlock through the local web portal and explicitly enable/reconnect the USB drive.
CDC status reports 1.1; the application image version is {version}.

## Existing filesystem geometry

Firmware updates do not convert existing 4 KiB-cluster FAT32 volumes. Newly
created virtual volumes >=4 GiB use 32 KiB clusters. Changing an existing
volume requires a verified backup, recreation of the virtual filesystem, and
restoration. Do not reformat the physical SD card as an upgrade step.

## Limits

This is development firmware. The measured 64 GB mount workload improved from
about 124 seconds to 30 seconds after virtual-filesystem recreation; mounting
is still not instantaneous. A 128 GB hardware test is not claimed. FAT32 retains
its individual-file size limit below 4 GiB. exFAT is not supported by this release.
Always safely eject before unplugging: acknowledged writes can remain in RAM.
See docs/VALIDATION.md and docs/THREAT_MODEL.md in the source repository.

## Integrity

SHA256SUMS lists SHA-256 hashes. On Windows, use Get-FileHash -Algorithm SHA256;
on Linux, use sha256sum -c SHA256SUMS. The ZIP includes its own payload checksum list.
''', encoding='utf-8')
    payload = sorted(args.output.iterdir())
    def checksum(paths):
        return ''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in paths)
    sums = args.output / 'SHA256SUMS'
    sums.write_text(checksum(payload), encoding='ascii')
    archive = args.output / f'esp32-vault-v{version}.zip'
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as package:
        for p in payload + [sums]:
            package.write(p, f'esp32-vault-v{version}/{p.name}')
    sums.write_text(checksum(payload + [archive]), encoding='ascii')
    print(f'Packaged v{version}: {len(app):,} application bytes, {len(payload) + 2} assets')


if __name__ == '__main__':
    main()
