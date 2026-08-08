#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 04_gps_override_demo_usb.py -- one-shot GPS "spoof" via the DEMO-ONLY
# debug hook (SPP_APID_TC_GPS_OVERRIDE, 0x14), delivered over FlatSat's
# real USB CDC serial link instead of RF. See 04_gps_override_demo_rf.py in
# this same folder for the full context.
#
# THIS IS NOT THE REAL RF GPS SPOOFING ATTACK, and unlike every other
# attack in this dossier, it has NO real-attack RF counterpart to speak
# of either way: 04_gps_spoofing_rf.py (the actual GPS L1 signal spoof,
# overpowering the FlatSat's real u-blox NEO-6M) has no USB equivalent at
# all -- it doesn't send a command to the flight computer, it attacks a
# separate physical GPS receiver by out-shouting the real satellite
# signal over the air. There is nothing to "do over USB" for that attack.
#
# This script is the USB port of the DEBUG-ONLY demo instead
# (SPP_APID_TC_GPS_OVERRIDE, 0x14) -- a command that only exists in a
# separate firmware build (firmware/gps-debug-demo/, NOT the real
# New-firmware/), added specifically to demonstrate what a successful GPS
# spoof would look like on the PWNSAT-C3 dashboard once the position is
# trusted with no plausibility check. Requires that debug build flashed to
# the FlatSat -- this command does not exist in the real firmware.
#
# Payload (13 bytes, matches commandGpsOverrideHandler() in worker.cpp):
#   lat_e7 (int32 LE), lon_e7 (int32 LE), alt_cm (int32 LE), satellites (u8)
#
# NOT YET VALIDATED ON REAL HARDWARE -- see lib/flatsat_usb.py's header.

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from flatsat_usb import FlatSatUSB  # noqa: E402

GPS_OVERRIDE_APID = 0x14

# Area 51 main base (Groom Lake / "Watertown") -- same target as the RF
# demo and the real (blocked) spoofing attempt.
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
    parser.add_argument("--port", default=None,
                        help="serial port for the USBRadioLink (default: autodetect)")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    print("=" * 66)
    print("PWNSAT GPS override DEMO (USB) -- debug hook, NOT the real RF GPS spoof")
    print("Requires firmware/gps-debug-demo/ flashed -- this command does not")
    print("exist in the real New-firmware/ build.")
    print(f"Target: lat={args.lat} lon={args.lon} alt={args.alt}m sats={args.sats}")
    print("=" * 66)

    payload = build_gps_override_payload(args.lat, args.lon, args.alt, args.sats)

    with FlatSatUSB(port=args.port, encrypt=True, verbose=not args.quiet) as fsat:
        fsat.send_raw_tc(GPS_OVERRIDE_APID, payload, seq=args.seq, listen_seconds=1.0)

    print(f"[+] Sent over USB. Check PWNSAT-C3's GPS/NAV panel and map -- the "
          f"position should jump to the target immediately (no wait for "
          f"reacquisition, unlike the real RF attack).")


if __name__ == "__main__":
    main()
