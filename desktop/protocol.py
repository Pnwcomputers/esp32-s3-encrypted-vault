"""USB CDC framing, command codecs and validated response parsers."""
from __future__ import annotations
import struct
import zlib
from dataclasses import dataclass

MAGIC = b"VLT1"
PROTOCOL_VERSION = 1
# magic[4], version[u8], command[u8], request_id[u32], payload_len[u32]
HEADER = struct.Struct("<4sBBII")
CRC = struct.Struct("<I")

@dataclass(frozen=True)
class Frame:
    command: int
    request_id: int
    payload: bytes = b""

def encode_frame(frame: Frame) -> bytes:
    if not (0 <= frame.command <= 255):
        raise ValueError("command must fit u8")
    if not (0 <= frame.request_id <= 0xFFFFFFFF):
        raise ValueError("request_id must fit u32")
    if len(frame.payload) > _payload_limit(frame.command):
        raise ValueError("payload too large")
    header = HEADER.pack(MAGIC, PROTOCOL_VERSION, frame.command,
                         frame.request_id, len(frame.payload))
    body = header + frame.payload
    return body + CRC.pack(zlib.crc32(body) & 0xFFFFFFFF)

def decode_frame(data: bytes) -> Frame:
    if len(data) < HEADER.size + CRC.size:
        raise ValueError("frame too short")
    magic, version, command, request_id, payload_len = HEADER.unpack_from(data)
    if magic != MAGIC:
        raise ValueError("bad magic")
    if version != PROTOCOL_VERSION:
        raise ValueError("unsupported protocol version")
    if payload_len > _payload_limit(command):
        raise ValueError("payload too large")
    expected_len = HEADER.size + payload_len + CRC.size
    if len(data) != expected_len:
        raise ValueError("frame length mismatch")
    expected_crc, = CRC.unpack_from(data, expected_len - CRC.size)
    actual_crc = zlib.crc32(data[:-CRC.size]) & 0xFFFFFFFF
    if expected_crc != actual_crc:
        raise ValueError("CRC mismatch")
    payload = data[HEADER.size:HEADER.size + payload_len]
    return Frame(command=command, request_id=request_id, payload=payload)

CMD_GET_STATUS = 0x01
CMD_GET_USB_DIAGNOSTICS = 0x02
CMD_LIST_FILES = 0x10
CMD_UPLOAD_BEGIN, CMD_UPLOAD_CHUNK, CMD_UPLOAD_COMMIT = 0x20, 0x21, 0x22
CMD_DOWNLOAD_BEGIN, CMD_DOWNLOAD_CHUNK, CMD_DOWNLOAD_END = 0x30, 0x31, 0x32
CMD_DELETE_FILE, CMD_LOCK = 0x40, 0x50
STATUS_OK, STATUS_ERR_LOCKED, STATUS_ERR_NOT_FOUND, STATUS_ERR_AUTH_FAIL = range(4)
STATUS_ERR_STORAGE, STATUS_ERR_INVALID_ARG, STATUS_ERR_BUSY, STATUS_ERR_NO_MEM = range(4, 8)
STATUS_MESSAGES = dict(enumerate(('OK', 'Vault is locked', 'File not found',
    'Authentication failed', 'Storage error', 'Invalid argument', 'Busy', 'Out of memory')))

# A request contains up to 4096 bytes plus file ID and chunk number.
MAX_PAYLOAD = 4224
MAX_LIST_PAYLOAD = 5 + 256 * (2 + 127 + 8 + 8 + 16)

def _payload_limit(command):
    return MAX_LIST_PAYLOAD if command == CMD_LIST_FILES else MAX_PAYLOAD

class FrameStreamDecoder:
    """Incrementally recover complete CRC-checked frames from a serial stream."""
    def __init__(self):
        self._buffer = bytearray()

    def feed(self, data: bytes) -> list[Frame]:
        frames = []
        for start in range(0, len(data), 512):
            frames.extend(self._feed_piece(data[start:start + 512]))
        return frames

    def _feed_piece(self, data: bytes) -> list[Frame]:
        self._buffer.extend(data)
        frames = []
        while True:
            offset = self._buffer.find(MAGIC)
            if offset < 0:
                self._buffer[:] = self._buffer[-3:]
                break
            if offset:
                del self._buffer[:offset]
            if len(self._buffer) < HEADER.size:
                break
            _, version, command, _, length = HEADER.unpack_from(self._buffer)
            if version != PROTOCOL_VERSION or length > _payload_limit(command):
                del self._buffer[0]
                continue
            total = HEADER.size + length + CRC.size
            if len(self._buffer) < total:
                break
            try:
                frames.append(decode_frame(bytes(self._buffer[:total])))
            except ValueError:
                del self._buffer[0]
            else:
                del self._buffer[:total]
        return frames

@dataclass(frozen=True)
class VaultStatus:
    is_unlocked: bool
    firmware_version: int
    total_space_mb: int
    free_space_mb: int
    file_count: int

    @property
    def used_space_mb(self):
        return max(0, self.total_space_mb - self.free_space_mb)

@dataclass(frozen=True)
class FileInfo:
    filename: str
    size: int
    modified: int
    file_id: bytes

    @property
    def file_id_hex(self):
        return self.file_id.hex()

def _exact(payload, length):
    if len(payload) != length:
        raise ValueError('Invalid response length')

def parse_status_response(payload):
    _exact(payload, 16)
    status, unlocked, version, total, free, count = struct.unpack('<BBHIII', payload)
    if status != STATUS_OK or unlocked not in (0, 1) or free > total:
        raise ValueError('Invalid status response')
    return VaultStatus(bool(unlocked), version, total, free, count)

def parse_list_files_response(payload):
    if len(payload) < 5:
        raise ValueError('Truncated list response')
    count, = struct.unpack_from('<I', payload, 1)
    if count > 256:
        raise ValueError('Too many file records')
    offset, files = 5, []
    for _ in range(count):
        if offset + 2 > len(payload):
            raise ValueError('Truncated filename length')
        n, = struct.unpack_from('<H', payload, offset)
        offset += 2
        # The length fields must stay sane: a bad length desynchronises every
        # following record, so that still fails the whole listing closed.
        if not 0 < n < 128 or offset + n + 32 > len(payload):
            raise ValueError('Invalid file record length')
        raw = payload[offset:offset+n]
        size, modified = struct.unpack_from('<QQ', payload, offset + n)
        file_id = payload[offset+n+16:offset+n+32]
        offset += n + 32
        # A single record whose name is not valid UTF-8 or violates the name
        # rules is skipped rather than aborting the entire listing. Upload-time
        # validation means such a record implies corruption/desync, not a normal
        # file, so dropping just that entry is the least-surprising behaviour.
        try:
            name = raw.decode('utf-8')
            _name(name)
        except ValueError:
            continue
        files.append(FileInfo(name, size, modified, file_id))
    _exact(payload, offset)
    return payload[0], files

def _name(name):
    encoded = name.encode('utf-8')
    if not 0 < len(encoded) < 128 or name in ('.', '..') or any(ord(c) < 32 or c in '/\\' for c in name):
        raise ValueError('Filename must be 1–127 UTF-8 bytes')
    return struct.pack('<H', len(encoded)) + encoded

def _id(file_id):
    if not isinstance(file_id, bytes) or len(file_id) != 16:
        raise ValueError('File ID must be 16 bytes')
    return file_id

def encode_upload_begin(name, size):
    if not 0 <= size <= 0xFFFFFFFF:
        raise ValueError('File exceeds supported 4 GiB minus 1 byte limit')
    return _name(name) + struct.pack('<Q', size)

def parse_upload_begin_response(payload):
    _exact(payload, 21)
    chunk_size, = struct.unpack_from('<I', payload, 17)
    if not 1 <= chunk_size <= 4096:
        raise ValueError('Invalid upload chunk size')
    return payload[0], payload[1:17], chunk_size

def encode_upload_chunk(file_id, index, data):
    if len(data) > 4096:
        raise ValueError('Chunk too large')
    return _id(file_id) + struct.pack('<I', index) + data

def parse_upload_chunk_response(payload):
    _exact(payload, 5)
    return payload[0], struct.unpack_from('<I', payload, 1)[0]

def encode_download_begin(target):
    if isinstance(target, bytes):
        return _id(target)
    if len(target) == 32 and all(c in '0123456789abcdefABCDEF' for c in target):
        return bytes.fromhex(target)
    encoded = _name(target)
    # Firmware distinguishes IDs by payload length; refuse the ambiguous legacy case.
    if len(encoded) == 16:
        raise ValueError('Use the file ID to download a filename of 14 UTF-8 bytes')
    return encoded

def parse_download_begin_response(payload):
    _exact(payload, 33)
    size, chunk_size, count = struct.unpack_from('<QII', payload, 17)
    if chunk_size != 4096 or size > 0xFFFFFFFF or count != max(1, (size+4095)//4096):
        raise ValueError('Invalid download dimensions')
    return payload[0], payload[1:17], size, chunk_size, count

def encode_download_chunk(file_id, index):
    return _id(file_id) + struct.pack('<I', index)

def parse_download_chunk_response(payload):
    if not 5 <= len(payload) <= 4101:
        raise ValueError('Invalid download chunk response')
    return payload[0], struct.unpack_from('<I', payload, 1)[0], payload[5:]
