#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 04_gps_override_demo.py -- one-shot GPS "spoof" via the DEMO-ONLY debug
# hook (SPP_APID_TC_GPS_OVERRIDE, 0x14) added to the firmware variant in
# firmware/gps-debug-demo/, sent over the same HackRF uplink every other
# attack in this dossier uses. Defaults to Area 51 (37.2431N, -115.7930W).
#
# THIS IS NOT THE REAL RF GPS SPOOFING ATTACK. Real RF spoofing against
# the FlatSat's actual u-blox NEO-6M was attempted extensively (single
# fixed position at 6 gain levels, sustained low gain, a smooth aligned
# hand-over, amp on/off, an 11-value ppm sweep) and confirmed blocked by
# a real, verified hardware limitation: `hackrf_debug --si5351c -n 0 -r`
# on this HackRF returned `[0] -> 0x51`, confirming no TCXO reference is
# active -- GPS L1 needs frequency precision this stock HackRF can't
# provide. See steps.txt for the full writeup and evidence.
#
# This script instead demonstrates what a SUCCESSFUL spoof would look
# like on the PWNSAT-C3 dashboard, using a debug command WE added to a
# separate firmware build (firmware/gps-debug-demo/, compiled from a full
# copy of New-firmware/ -- the real firmware is untouched, see that
# folder's own platformio.ini comment). Requires that build flashed to
# the FlatSat instead of the real firmware -- it will NOT work against
# New-firmware/ as compiled today, since that command doesn't exist
# there. Be explicit about this distinction if demoing live: this proves
# "GPS telemetry is trusted with no integrity/plausibility check," not
# "the GPS radio link itself was spoofed" (that's the real attack, and
# it's the one that's still blocked by the missing TCXO).
#
# Payload (13 bytes, matches commandGpsOverrideHandler() in worker.cpp):
#   lat_e7 (int32 LE), lon_e7 (int32 LE), alt_cm (int32 LE), satellites (u8)

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from pwnsat_packets import build_tc, decode_packet, decrypt_payload, encrypt_payload  # noqa: E402

from require_gnuradio import check as _check_gnuradio  # noqa: E402
_check_gnuradio()  # exits with a clear message here if this Python can't import gnuradio

from pwnsat_lora_tx import UPLINK_FREQ_HZ, transmit_packet  # noqa: E402
from pwnsat_catsniffer_rx import CatSnifferRX  # noqa: E402
from pwnsat_rtlsdr_rx import RtlSdrRX  # noqa: E402

GPS_OVERRIDE_APID = 0x14
NAV_TM_APID = 0x0E  # SPP_APID_TM_NAV -- commandGpsOverrideHandler() replies with this

# Area 51 main base (Groom Lake / "Watertown") -- same target as the
# real spoofing attempt in 04_gps_spoofing.py/spoof_ramp.sh.
DEFAULT_LAT = 37.2431
DEFAULT_LON = -115.7930
DEFAULT_ALT_M = 1360.0
DEFAULT_SATS = 10


def build_gps_override_payload(lat: float, lon: float, alt_m: float, sats: int) -> bytes:
    lat_e7 = int(round(lat * 1e7))
    lon_e7 = int(round(lon * 1e7))
    alt_cm = int(round(alt_m * 100))
    return (
        lat_e7.to_bytes(4, "little", signed=True)
        + lon_e7.to_bytes(4, "little", signed=True)
        + alt_cm.to_bytes(4, "little", signed=True)
        + bytes([sats & 0xFF])
    )


def parse_nav_tm(raw: bytes) -> dict:
    """Decrypts+unpacks a NAV TM payload -- layout matches
    telemetrySPPTransmitNavSnapshot() in worker.cpp: spacecraft_id(1)
    gps_status(1) satellites(1) lat_e7(i32 LE) lon_e7(i32 LE) alt_cm(i32 LE) ..."""
    pkt = decode_packet(raw)
    plain = decrypt_payload(pkt.data)
    if len(plain) < 15:
        raise ValueError(f"NAV TM payload too short: {len(plain)} bytes")
    return {
        "satellites": plain[2],
        "lat_e7": int.from_bytes(plain[3:7], "little", signed=True),
        "lon_e7": int.from_bytes(plain[7:11], "little", signed=True),
        "alt_cm": int.from_bytes(plain[11:15], "little", signed=True),
    }


def find_nav_reply(frames: list, verbose: bool):
    for frame in frames:
        raw = getattr(frame, "raw", frame)
        try:
            pkt = decode_packet(raw)
        except ValueError:
            continue
        if pkt.packet_type == 1:
            continue  # our own uplink leaking into the RX
        if pkt.apid != NAV_TM_APID:
            continue
        try:
            return parse_nav_tm(raw)
        except ValueError as exc:
            if verbose:
                print(f"    (NAV-shaped frame, couldn't parse: {exc})")
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lat", type=float, default=DEFAULT_LAT,
                        help=f"fake latitude, decimal degrees (default {DEFAULT_LAT}, Area 51)")
    parser.add_argument("--lon", type=float, default=DEFAULT_LON,
                        help=f"fake longitude, decimal degrees (default {DEFAULT_LON})")
    parser.add_argument("--alt", type=float, default=DEFAULT_ALT_M,
                        help=f"fake altitude, meters (default {DEFAULT_ALT_M})")
    parser.add_argument("--sats", type=int, default=DEFAULT_SATS,
                        help=f"fake satellite count to report (default {DEFAULT_SATS})")
    parser.add_argument("--seq", type=int, default=1, help="starting SPP sequence count")
    parser.add_argument("--tx-gain", type=int, default=20, help="HackRF TX (VGA) gain, dB")
    parser.add_argument("--frequency", type=int, default=UPLINK_FREQ_HZ,
                        help=f"uplink frequency, Hz (default {UPLINK_FREQ_HZ})")
    parser.add_argument("--rx-device", choices=("rtlsdr", "catsniffer", "none"), default="rtlsdr",
                        help="dedicated RX radio to confirm the override actually landed "
                             "(default rtlsdr; stop C3's own RTL-SDR bridge first if using "
                             "this; pass 'none' to skip confirmation entirely and just fire "
                             "the TC, old behavior)")
    parser.add_argument("--catsniffer-port", default=None,
                        help="only used with --rx-device catsniffer")
    parser.add_argument("--rx-gain", type=int, default=30,
                        help="only used with --rx-device rtlsdr")
    parser.add_argument("--listen-seconds", type=float, default=1.5,
                        help="how long to wait after TX before checking the RX")
    parser.add_argument("--retries", type=int, default=3,
                        help="confirmation attempts before giving up (RF noise/packet loss) "
                             "-- each retry re-sends the same TC")
    parser.add_argument("--quiet", action="store_true",
                        help="hide hackrf_transfer's own output and the RX device's status messages")
    args = parser.parse_args()

    print("=" * 66)
    print("PWNSAT GPS override DEMO -- debug hook, NOT the real RF GPS spoof")
    print("(see this script's own header and steps.txt for the distinction)")
    print(f"Target: lat={args.lat} lon={args.lon} alt={args.alt}m sats={args.sats}")
    print("=" * 66)

    payload = build_gps_override_payload(args.lat, args.lon, args.alt, args.sats)
    raw_spp = build_tc(GPS_OVERRIDE_APID, encrypt_payload(payload), args.seq)
    target_lat_e7 = int(round(args.lat * 1e7))
    target_lon_e7 = int(round(args.lon * 1e7))

    if args.rx_device == "none":
        print(f"[*] TC APID 0x{GPS_OVERRIDE_APID:03X} (GPS_OVERRIDE), seq={args.seq}, "
              f"payload={payload.hex()}")
        t0 = time.time()
        transmit_packet(raw_spp, frequency=args.frequency, device_args="hackrf",
                        tx_gain=args.tx_gain, verbose=not args.quiet)
        print(f"[+] Sent in {time.time()-t0:.3f}s -- --rx-device none, not confirmed "
              f"(fire-and-forget, old behavior). Check PWNSAT-C3's GPS/NAV panel by hand.")
        print("    Requires firmware/gps-debug-demo/firmware-debug-gps.uf2 flashed -- this ")
        print("    command does not exist in the real New-firmware/ build.")
        return

    if args.rx_device == "catsniffer":
        rx = CatSnifferRX(port=args.catsniffer_port, verbose=not args.quiet)
    else:
        rx = RtlSdrRX(rf_gain=args.rx_gain, verbose=not args.quiet)
    rx.start()
    time.sleep(0.5)

    try:
        confirmed = False
        for attempt in range(1, args.retries + 1):
            print(f"\n[*] TC APID 0x{GPS_OVERRIDE_APID:03X} (GPS_OVERRIDE), seq={args.seq}, "
                  f"payload={payload.hex()} (attempt {attempt}/{args.retries})")
            t0 = time.time()
            transmit_packet(raw_spp, frequency=args.frequency, device_args="hackrf",
                            tx_gain=args.tx_gain, verbose=not args.quiet)
            time.sleep(args.listen_seconds)
            frames = rx.take_since(t0)
            reply = find_nav_reply(frames, verbose=not args.quiet)
            if reply is None:
                print("    -> no NAV reply yet, retrying...")
                continue
            match = (reply["lat_e7"] == target_lat_e7 and reply["lon_e7"] == target_lon_e7)
            if match:
                print(f"    -> CONFIRMED: FlatSat's own NAV telemetry now reports "
                      f"lat_e7={reply['lat_e7']} lon_e7={reply['lon_e7']} "
                      f"alt_cm={reply['alt_cm']} sats={reply['satellites']} -- matches target.")
                confirmed = True
            else:
                print(f"    -> got a NAV reply, but it does NOT match the target yet "
                      f"(lat_e7={reply['lat_e7']} lon_e7={reply['lon_e7']} vs target "
                      f"lat_e7={target_lat_e7} lon_e7={target_lon_e7}) -- likely stale, retrying...")
                continue
            break

        print("\n" + "=" * 66)
        if confirmed:
            print("[+] GPS override confirmed via NAV telemetry -- position spoof landed.")
        else:
            print("[?] Could not confirm via RF in time -- inconclusive, NOT necessarily a")
            print("    failure (same RX packet-loss caveat as the other attacks in this")
            print("    dossier). Check PWNSAT-C3's NAV panel directly, or the gs-status")
            print("    range gate, before assuming the override didn't land.")
        print("=" * 66)
        print("    Requires firmware/gps-debug-demo/firmware-debug-gps.uf2 flashed -- this ")
        print("    command does not exist in the real New-firmware/ build.")
    finally:
        rx.close()


if __name__ == "__main__":
    main()
