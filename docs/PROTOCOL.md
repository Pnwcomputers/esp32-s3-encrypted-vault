# USB CDC protocol v1

The implementation is in `firmware/main/cdc_protocol.c`; host codecs are in `desktop/protocol.py`.
Native USB CDC-ACM transports framed requests and responses alongside the optional
encrypted USB mass-storage drive.
Unlock through the persistent Wi-Fi controller. USB never accepts a PIN or key export request.

## Frame

All integers are little endian. A frame contains `VLT1` (4 bytes), version (u8, 1),
command (u8), request ID (u32), payload byte length (u32), payload, then CRC32 (u32).
CRC32 uses the standard IEEE/zlib polynomial and covers the complete header and payload.
CRC detects accidental corruption; it provides no authentication or confidentiality.
Request payloads are bounded at 4224 bytes. LIST_FILES responses can contain up to
41221 bytes (256 records with maximum-length names); all other responses are bounded at 4224.
Responses echo the command and request ID. The first payload byte is the status.
Firmware 1.1.0 reports version `0x0101` in GET_STATUS; this field encodes only
major/minor, while the application image carries the full semantic version.

## Commands and payloads

| Command | Request | Successful response after status byte |
|---|---|---|
| `01 GET_STATUS` | Empty | unlocked u8, firmware version u16, total MB u32, free MB u32, file count u32 |
| `02 GET_USB_DIAGNOSTICS` | Empty | ASCII key=value fields: ready, reads, writes, errors, error_lba, error_bytes, error, max_ms, stage |
| `10 LIST_FILES` | Empty | count u32, then records: name length u16, UTF-8 name, size u64, modified time u64, ID[16] |
| `20 UPLOAD_BEGIN` | name length u16, UTF-8 name, total size u64 | ID[16], chunk size u32 (4096) |
| `21 UPLOAD_CHUNK` | ID[16], index u32, bytes | acknowledged index u32 |
| `22 UPLOAD_COMMIT` | ID[16] | Empty |
| `30 DOWNLOAD_BEGIN` | ID[16], or name length u16 plus UTF-8 name | ID[16], size u64, chunk size u32, total chunks u32 |
| `31 DOWNLOAD_CHUNK` | ID[16], index u32 | index u32, plaintext bytes |
| `32 DOWNLOAD_END` | ID[16] | Empty |
| `40 DELETE_FILE` | ID[16] | Empty |
| `50 LOCK` | Empty | Empty |

Status codes: 0 OK, 1 locked, 2 not found, 3 authentication failure, 4 storage error,
5 invalid argument, 6 busy, 7 out of memory. Error payloads contain only a status byte.
GET_STATUS, GET_USB_DIAGNOSTICS and LOCK are useful while locked; status omits
storage metadata then. Diagnostics are also allowed while MSC is exported.
They contain counters and the first failing transfer's location/result, but no
file contents, names, credentials or keys. Counters reset on device restart;
the storage failure stage survives drive close. This command does not unlock.

Files are limited to 4 GiB minus 1 byte and names to 127 UTF-8 bytes. A chunk is exactly
4096 bytes except the final chunk. An empty file has one authenticated zero-byte chunk.
Commit requires all expected chunks. Upload chunks are sequential and duplicates fail;
there is no retransmission or resume protocol. Download chunks are consumed sequentially.
The v1 name/ID distinction is ambiguous for names of exactly 14 UTF-8 bytes; the host
client resolves names to IDs before downloading.

The desktop client serializes command exchanges, uses monotonically advancing request
IDs, checks acknowledgements and sizes, and does not automatically replay commands after
timeouts. Request IDs are correlation identifiers, not cryptographic replay protection.
An interrupted USB upload can hold its slot until LOCK or idle timeout. CDC shutdown waits
for its worker before freeing receive storage. Disconnect/session behavior still requires
physical USB validation. USB commands follow the device's global unlock state.
