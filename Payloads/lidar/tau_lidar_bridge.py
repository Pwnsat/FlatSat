#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# FlatSat LiDAR payload bridge.
#
# Runs on the payload-host processor (Raspberry Pi / laptop) attached to the Tau
# LiDAR Camera over USB. It reads depth frames, reduces them (tau_lidar_payload)
# and forwards each reduced summary to the FlatSat OBC as a CCSDS telecommand
# (SPP_APID_TC_SET_LIDAR_FRAME), reusing the repo's own SPP builder rather than
# re-deriving the wire format.
#
#   Tau camera --USB--> [this bridge] --CCSDS/serial--> FlatSat OBC --RF--> ground
#
# --simulate synthesizes depth frames so the whole pipeline runs with no camera
# and no board; --dry-run prints the telecommand bytes instead of transmitting.
from __future__ import annotations

import argparse
import math
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tau_lidar_payload import (  # noqa: E402
    FRAME_HEIGHT,
    FRAME_TYPE_DISTANCE_AMPLITUDE,
    FRAME_WIDTH,
    build_lidar_payload,
    reduce_frame,
)

# APIDs -- mirror Firmware/mission.h.
SPP_APID_TC_SET_LIDAR_FRAME = 0x15
SPP_APID_TC_GET_LIDAR = 0x14


def _mm(value):
    return "----" if value == 0xFFFF else ("%dmm" % value)


class PayloadLink:
    """Transport to the OBC. Uses the repo's FlatSatUSB (Attacks/lib) when the
    board and full pwnsat toolchain are present; otherwise falls back to a
    dry-run that prints the telecommand bytes, so the bridge is always runnable.
    """

    def __init__(self, *, obc_port=None, encrypt=True, dry_run=False, verbose=True):
        self.dry_run = dry_run
        self.verbose = verbose
        self._fsat = None
        if dry_run:
            return
        try:
            lib = Path(__file__).resolve().parents[2] / "Attacks" / "lib"
            sys.path.insert(0, str(lib))
            from flatsat_usb import FlatSatUSB  # noqa: E402

            self._fsat = FlatSatUSB(port=obc_port, encrypt=encrypt, verbose=verbose)
            self._fsat.__enter__()
        except Exception as exc:  # missing board or pwnsat_tools -> dry-run
            print(
                "[warn] OBC link unavailable (%s); falling back to --dry-run"
                % exc,
                file=sys.stderr,
            )
            self.dry_run = True
            self._fsat = None

    def send_frame(self, payload, seq):
        if self.dry_run or self._fsat is None:
            print("  TC SET_LIDAR_FRAME (%d B): %s" % (len(payload), payload.hex()))
            return
        # send_raw_tc(apid, payload, *, seq=...) -- encrypts + frames + sends.
        self._fsat.send_raw_tc(SPP_APID_TC_SET_LIDAR_FRAME, payload, seq=seq)

    def close(self):
        if self._fsat is not None:
            try:
                self._fsat.__exit__(None, None, None)
            except Exception:
                pass
            self._fsat = None


def simulate_frame(width, height, frame_count):
    """Synthesize a plausible depth scene (distances in mm): a background wall
    that recedes left-to-right (~1800..2200 mm), a nearer object drifting across
    the centre (~700 mm), and a dead band of no-return pixels along the top."""
    depth = [0.0] * (width * height)
    amp = [0] * (width * height)
    center_x = width // 2 + int(20 * math.sin(frame_count / 5.0))
    center_y = height // 2
    for y in range(height):
        for x in range(width):
            i = y * width + x
            if y < 4:  # dead band: no return
                depth[i] = 0.0
                amp[i] = 0
                continue
            d = 1800.0 + (x / max(1, width - 1)) * 400.0
            if abs(x - center_x) < 18 and abs(y - center_y) < 12:
                d = 700.0 + 50.0 * math.sin(frame_count / 3.0)
            depth[i] = d
            amp[i] = 400
    return depth, amp


def emit(link, summary, seq):
    payload = build_lidar_payload(summary)
    print(
        "LiDAR frame #%d: min=%s mean=%s center=%s max=%s valid=%d%% ampl=%d "
        "status=0x%02X"
        % (
            summary.frame_count,
            _mm(summary.min_mm),
            _mm(summary.mean_mm),
            _mm(summary.center_mm),
            _mm(summary.max_mm),
            summary.valid_pct,
            summary.amplitude,
            summary.status,
        )
    )
    link.send_frame(payload, seq)


def run_simulate(args, link):
    frame_count = 0
    while args.frames <= 0 or frame_count < args.frames:
        depth, amp = simulate_frame(FRAME_WIDTH, FRAME_HEIGHT, frame_count)
        summary = reduce_frame(
            depth,
            FRAME_WIDTH,
            FRAME_HEIGHT,
            amplitude=amp,
            frame_type=FRAME_TYPE_DISTANCE_AMPLITUDE,
            frame_count=frame_count,
            amplitude_floor=args.amplitude_floor,
        )
        emit(link, summary, frame_count & 0x3FFF)
        frame_count += 1
        if args.frames <= 0 or frame_count < args.frames:
            time.sleep(args.interval)
    return 0


def run_camera(args, link):
    # Lazy import: only the live path needs the camera SDK.
    from TauLidarCamera.camera import Camera
    from TauLidarCommon.frame import FrameType

    ports = Camera.scan()
    port = args.port or (ports[0] if ports else None)
    if port is None:
        print(
            "No Tau LiDAR Camera found. Use --simulate to run without hardware.",
            file=sys.stderr,
        )
        return 2

    Camera.setRange(0, 4500)
    camera = Camera.open(port)
    camera.setModulationChannel(0)
    camera.setIntegrationTime3d(0, 800)
    camera.setMinimalAmplitude(0, 60)
    info = camera.info()
    print(
        "Tau LiDAR opened: model=%s fw=%s uid=%s res=%s port=%s"
        % (info.model, info.firmware, info.uid, info.resolution, info.port)
    )

    frame_count = 0
    try:
        while args.frames <= 0 or frame_count < args.frames:
            frame = camera.readFrame(FrameType.DISTANCE_AMPLITUDE)
            if frame:
                depth = list(frame.data_depth)  # float32 mm, row-major
                amp = list(frame.data_amplitude) if frame.data_amplitude else None
                summary = reduce_frame(
                    depth,
                    frame.width,
                    frame.height,
                    amplitude=amp,
                    frame_type=FRAME_TYPE_DISTANCE_AMPLITUDE,
                    frame_count=frame_count,
                    amplitude_floor=args.amplitude_floor,
                )
                emit(link, summary, frame_count & 0x3FFF)
                frame_count += 1
            if args.frames <= 0 or frame_count < args.frames:
                time.sleep(args.interval)
    finally:
        camera.close()
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        description="FlatSat Tau LiDAR payload bridge: read depth frames, reduce "
        "them, forward to the OBC as CCSDS telemetry."
    )
    parser.add_argument(
        "--simulate",
        action="store_true",
        help="synthesize depth frames instead of reading a camera (no hardware)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the telecommand bytes instead of transmitting to the OBC",
    )
    parser.add_argument(
        "--port", default=None, help="Tau LiDAR serial port (default: autodetect)"
    )
    parser.add_argument(
        "--obc-port", default=None, help="FlatSat OBC serial port (default: autodetect)"
    )
    parser.add_argument(
        "--frames",
        type=int,
        default=0,
        help="number of frames to send then exit (0 = run until Ctrl-C)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="seconds between frames (default: 1.0)",
    )
    parser.add_argument(
        "--amplitude-floor",
        type=int,
        default=0,
        help="drop pixels whose amplitude is below this value (0 = disabled)",
    )
    parser.add_argument(
        "--no-encrypt",
        dest="encrypt",
        action="store_false",
        help="send telecommands without the FlatSat secure link",
    )
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    link = PayloadLink(
        obc_port=args.obc_port, encrypt=args.encrypt, dry_run=args.dry_run
    )
    try:
        if args.simulate:
            return run_simulate(args, link)
        return run_camera(args, link)
    except KeyboardInterrupt:
        return 0
    finally:
        link.close()


if __name__ == "__main__":
    sys.exit(main())
