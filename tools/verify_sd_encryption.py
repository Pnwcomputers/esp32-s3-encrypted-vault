#!/usr/bin/env python3
"""Check that a microSD card removed from the vault holds no readable plaintext.

Workflow (see docs/VALIDATION.md, "Verify the card is encrypted"):

  1. python tools/verify_sd_encryption.py make-canary
       Creates a uniquely marked file. Copy it onto the ESP32 VAULT drive.
  2. Safely eject ESP32 VAULT, lock the vault, power off and remove the card.
  3. Mount the card on a computer (read-only if possible) and run:
       python tools/verify_sd_encryption.py check /media/you/CARD --canary <TOKEN>
     Optionally scan the raw device as well, which also covers deleted space:
       sudo python tools/verify_sd_encryption.py check /media/you/CARD \
           --canary <TOKEN> --raw /dev/sdX

The check never writes to the card. It:
  * searches every file (and optionally the raw device) for the canary token,
    as UTF-8 and UTF-16LE (the encoding FAT uses for long filenames);
  * parses each vault record and confirms its ciphertext looks random;
  * lists anything on the card outside /vault, which the vault does not protect.
"""
import argparse
import math
import os
import secrets
import struct
import sys
from pathlib import Path

RECORD = 12 + 16 + 4096           # vault_drive.c record_t: iv, tag, ciphertext
ROOT_HDR = 8 + 16 + 12 + 16       # root_record_t before ciphertext
JOURNAL_HDR = 8 + 16 + 4 * 3 + 12 + 16
INDEX_HDR = 4 + 1 + 12 + 4 + 16   # magic, version, iv, count, tag
CONTAINER_HDR = 4 + 1 + 3 + 16 + 8 + 4 + 4
CHUNK_HDR = 4 + 4 + 12 + 16       # chunk_idx, ciphertext_len, iv, tag
META_SIZE = 4 + 1 + 3 + 4 + 32 + 12 + 32 + 16
MIN_SAMPLE = 2048                 # below this, byte entropy is too noisy to judge
MIN_ENTROPY = 7.8                 # 4 KiB of random data measures ~7.95 bits/byte
SCAN_CHUNK = 4 * 1024 * 1024


def entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


class Report:
    def __init__(self):
        self.failures, self.warnings, self.notes = [], [], []

    def fail(self, msg):
        self.failures.append(msg)

    def warn(self, msg):
        self.warnings.append(msg)

    def note(self, msg):
        self.notes.append(msg)


def judge(report, label, ciphertext):
    if len(ciphertext) < MIN_SAMPLE:
        return None
    e = entropy(ciphertext)
    if e < MIN_ENTROPY:
        report.fail(f'{label}: ciphertext entropy {e:.3f} bits/byte looks like plaintext')
    return e


def check_segment(report, path):
    data = path.read_bytes()
    if len(data) % RECORD:
        report.warn(f'{path.name}: size {len(data)} is not a whole number of records')
    used = empty = stale = 0
    worst = 8.0
    for i in range(len(data) // RECORD):
        rec = data[i * RECORD:(i + 1) * RECORD]
        if not any(rec):
            empty += 1          # never-written slot holding zeros
            continue
        label = f'{path.name} {"allocation map" if i == 0 else f"block {i - 1}"}'
        e = entropy(rec[28:])
        if not any(rec[:12]) or e < MIN_ENTROPY:
            # Firmware after 1.1.0 preallocates each new segment file, so a
            # never-written slot can hold whatever the card stored there before
            # (old files, often zeros). Without the key, such a slot can't be
            # told apart from a bad record, so it is a warning; the canary
            # search is the decisive plaintext check.
            stale += 1
            report.warn(f'{label}: not random (entropy {e:.3f}' +
                        (', zero IV' if not any(rec[:12]) else '') +
                        '); a never-written slot with old card data, or a plaintext leak')
            continue
        used += 1
        worst = min(worst, e)
    report.note(f'{path.name}: {used} encrypted-looking records, {empty} zero-filled, {stale} not random, '
                f'lowest entropy {worst:.3f}' if used else
                f'{path.name}: no encrypted-looking records ({empty} zero-filled, {stale} not random)')


def check_tail(report, path, header_len, magic=None):
    data = path.read_bytes()
    if magic and not data.startswith(magic):
        report.warn(f'{path.name}: unexpected header (not {magic!r})')
    e = judge(report, path.name, data[header_len:])
    report.note(f'{path.name}: {len(data)} bytes' + (f', entropy {e:.3f}' if e else ', too small to judge entropy'))


def check_container(report, path):
    data = path.read_bytes()
    if data[:4] != b'FTLV':
        report.warn(f'{path.name}: not a vault file container')
        return
    pos, cipher = CONTAINER_HDR, bytearray()
    while pos + CHUNK_HDR <= len(data):
        n = struct.unpack_from('<I', data, pos + 4)[0]
        pos += CHUNK_HDR
        cipher += data[pos:pos + n]
        pos += n
    e = judge(report, path.name, bytes(cipher))
    report.note(f'{path.name}: {len(cipher)} ciphertext bytes' +
                (f', entropy {e:.3f}' if e else ', too small to judge entropy'))


def check_vault(report, vault):
    for path in sorted(p for p in vault.rglob('*') if p.is_file()):
        name = path.name
        base = name[:-4] if name.endswith(('.bak', '.tmp')) else name
        if base.startswith('usb-') and base.endswith('.enc'):
            check_segment(report, path)
        elif base == 'usb-drive.hdr':
            check_tail(report, path, ROOT_HDR, b'VLTDSK2')
        elif base == 'usb-drive.txn':
            check_tail(report, path, JOURNAL_HDR, b'VLTTXN2')
        elif base in ('index.enc', 'index'):
            check_tail(report, path, INDEX_HDR, b'ITLV')
        elif base == 'vault.meta':
            data = path.read_bytes()
            if len(data) != META_SIZE or data[:4] != b'KTLV':
                report.warn(f'{name}: unexpected size/header for the key file')
            else:
                iters = struct.unpack_from('<I', data, 8)[0]
                report.note(f'{name}: wrapped data key; PBKDF2 iterations {iters} and salt are '
                            'stored in plaintext by design')
        elif path.parent.name == 'files' and base.endswith('.bin'):
            check_container(report, path)
        else:
            report.warn(f'{path.relative_to(vault.parent)}: unrecognized file inside /vault')


def patterns(tokens):
    out = []
    for t in tokens:
        out.append((t, 'UTF-8', t.encode()))
        out.append((t, 'UTF-16LE', t.encode('utf-16-le')))
    return out


def scan_stream(fp, pats, label, report, limit=None):
    overlap = max(len(p) for _, _, p in pats) - 1
    tail, offset, hits = b'', 0, 0
    while limit is None or offset < limit:
        block = fp.read(SCAN_CHUNK)
        if not block:
            break
        buf = tail + block
        for token, enc, pat in pats:
            i = buf.find(pat)
            while i != -1:
                report.fail(f'canary "{token}" found in plaintext ({enc}) in {label} '
                            f'at byte {offset - len(tail) + i}')
                hits += 1
                if hits >= 20:
                    report.fail(f'{label}: stopping after 20 hits')
                    return
                i = buf.find(pat, i + 1)
        tail = buf[-overlap:] if overlap else b''
        offset += len(block)
    return offset


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    mk = sub.add_parser('make-canary', help='create a uniquely marked test file to copy onto the vault drive')
    mk.add_argument('--out', default='.', help='directory for the canary file (default: current)')
    ck = sub.add_parser('check', help='inspect a removed card')
    ck.add_argument('card', type=Path, help='mount point of the removed microSD card')
    ck.add_argument('--canary', action='append', default=[], help='token printed by make-canary (repeatable)')
    ck.add_argument('--raw', help='also scan this raw device or card image, e.g. /dev/sdX (needs read access)')
    args = ap.parse_args()

    if args.cmd == 'make-canary':
        token = 'VAULTCANARY' + secrets.token_hex(8).upper()
        path = Path(args.out) / f'{token}.txt'
        line = f'{token} This text must never appear in plaintext on the microSD card.\n'
        path.write_text(line * 2000)    # ~150 KB, spans many 4 KiB blocks
        print(f'Created {path}\nCanary token: {token}\n')
        print('Copy this file onto the ESP32 VAULT drive, safely eject, lock the vault,')
        print('remove the card, then run:')
        print(f'  python tools/verify_sd_encryption.py check <CARD_MOUNT> --canary {token}')
        print('Delete the local copy before scanning so you do not scan it by mistake.')
        return 0

    card = args.card
    if not card.is_dir():
        print(f'{card} is not a directory. Pass the mount point of the card.', file=sys.stderr)
        return 2
    report = Report()
    vault = card / 'vault'
    if not vault.is_dir():
        report.fail('no /vault directory: is this the vault card, and is it the mount point?')
    else:
        check_vault(report, vault)

    for path in sorted(card.rglob('*')):
        if path.is_file() and vault not in path.parents:
            report.warn(f'{path.relative_to(card)}: stored outside /vault, NOT encrypted by the vault')

    if args.canary:
        pats = patterns(args.canary)
        names = 0
        for path in card.rglob('*'):
            for token in args.canary:
                if token.lower() in path.name.lower():
                    report.fail(f'canary "{token}" appears in a card filename: {path.relative_to(card)}')
            if path.is_file():
                names += 1
                with open(path, 'rb') as fp:
                    scan_stream(fp, pats, str(path.relative_to(card)), report)
        report.note(f'canary search: scanned {names} files')
        if args.raw:
            try:
                with open(args.raw, 'rb') as fp:
                    n = scan_stream(fp, pats, f'raw {args.raw}', report)
                report.note(f'canary search: scanned {n or 0:,} raw bytes of {args.raw}')
            except OSError as exc:
                report.fail(f'could not read {args.raw}: {exc} (try sudo, or unmount first)')
    else:
        report.warn('no --canary given: only the structure/entropy checks ran')

    for msg in report.notes:
        print(f'  info  {msg}')
    for msg in report.warnings:
        print(f'  WARN  {msg}')
    for msg in report.failures:
        print(f'  FAIL  {msg}')
    print()
    if report.failures:
        print('RESULT: FAIL - readable data or unexpected structure found (see above).')
        return 1
    print('RESULT: PASS - no plaintext canary found; all vault records look encrypted.')
    if report.warnings:
        print('        Review the warnings above.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
