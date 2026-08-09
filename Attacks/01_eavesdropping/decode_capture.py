#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# decode_capture.py -- offline replay of a saved eavesdropping capture.
#
# pwnsat_rx_bridge.py (--output-file) saves each packet as a raw record:
# [8-byte timestamp_ns][2-byte length][raw SPP bytes], undecrypted on disk
# so the same file can also feed the replay attack (06).
#
# This reads that file back and runs the same header-parse / ECB-check /
# decrypt analysis pwnsat_rx_bridge.py prints live -- no HackRF, no gnuradio
# (only imports lib/decrypt_display.py and lib/pwnsat_packets.py).
#
# Example:
#   ./decode_capture.py eavesdrop_run1.bin

import argparse
import struct
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
from decrypt_display import hexdump, try_decrypt_packet  # noqa: E402

RECORD_HEADER_FORMAT = "<QH"  # matches pwnsat_rx_bridge.py's file_write_frame
RECORD_HEADER_SIZE = struct.calcsize(RECORD_HEADER_FORMAT)


def iter_capture_records(path: Path):
    """Yields (index, timestamp_ns, raw_spp_bytes) for every record in a
    capture file written by pwnsat_rx_bridge.py's --output-file. Raises
    ValueError if the file is truncated mid-record (e.g. the capture was
    cut off by Ctrl+C at exactly the wrong instant) -- reported per-record
    below instead of silently dropping the rest of the file."""
    with open(path, "rb") as f:
        data = f.read()

    offset = 0
    index = 0
    while offset < len(data):
        if offset + RECORD_HEADER_SIZE > len(data):
            raise ValueError(
                f"truncated record header at byte {offset} "
                f"({len(data) - offset} bytes left, need {RECORD_HEADER_SIZE})"
            )
        ts_ns, length = struct.unpack_from(RECORD_HEADER_FORMAT, data, offset)
        offset += RECORD_HEADER_SIZE

        if offset + length > len(data):
            raise ValueError(
                f"truncated packet body at byte {offset} "
                f"(declared {length} bytes, only {len(data) - offset} left)"
            )
        raw_spp = data[offset:offset + length]
        offset += length

        yield index, ts_ns, raw_spp
        index += 1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture_file", help="Path to a .bin file written by pwnsat_rx_bridge.py --output-file")
    args = parser.parse_args()

    path = Path(args.capture_file)
    if not path.exists():
        print(f"[!] {path} does not exist", file=sys.stderr)
        sys.exit(1)

    print("=" * 60)
    print(f"Offline replay of {path} -- no radio hardware involved")
    print("=" * 60 + "\n")

    count = 0
    try:
        for index, ts_ns, raw_spp in iter_capture_records(path):
            when = datetime.fromtimestamp(ts_ns / 1e9).strftime("%Y-%m-%d %H:%M:%S.%f")
            print(f"\n=========== PACKET #{index} (captured {when}) ===========")
            print(f"Length: {len(raw_spp)}")
            print(hexdump(raw_spp))
            print(try_decrypt_packet(raw_spp))
            count += 1
    except ValueError as exc:
        print(f"\n[!] stopped early: {exc}", file=sys.stderr)

    print(f"\n[*] {count} packet(s) replayed from {path}")


if __name__ == "__main__":
    main()
