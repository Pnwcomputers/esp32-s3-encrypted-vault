"""Read USB-drive diagnostics without unlocking or changing stored data."""
import argparse
from datetime import datetime, timezone
from pathlib import Path
import sys
import time

import serial

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from desktop.protocol import CMD_GET_USB_DIAGNOSTICS, Frame, FrameStreamDecoder, encode_frame


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', required=True)
    parser.add_argument('--seconds', type=float, default=0,
                        help='Monitor for this duration; default queries once')
    args = parser.parse_args()
    if args.seconds < 0:
        parser.error('--seconds must be nonnegative')
    decoder = FrameStreamDecoder()
    until = time.monotonic() + args.seconds
    request_id = 0
    with serial.Serial(args.port, 115200, timeout=0.2, write_timeout=2) as port:
        while True:
            request_id += 1
            port.write(encode_frame(Frame(CMD_GET_USB_DIAGNOSTICS, request_id)))
            deadline = time.monotonic() + 3
            answer = None
            while answer is None and time.monotonic() < deadline:
                for frame in decoder.feed(port.read(4096)):
                    if frame.command == CMD_GET_USB_DIAGNOSTICS and frame.request_id == request_id:
                        answer = frame.payload
            stamp = datetime.now(timezone.utc).isoformat(timespec='seconds')
            if not answer:
                raise RuntimeError('Diagnostic response timed out; no requests retried')
            if answer[0]:
                raise RuntimeError(f'Diagnostics rejected: status {answer[0]}')
            print(stamp, answer[1:].decode('ascii'), flush=True)
            if time.monotonic() >= until:
                break
            time.sleep(1)


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, serial.SerialException) as error:
        print(f'Diagnostic error: {error}', file=sys.stderr)
        sys.exit(1)
