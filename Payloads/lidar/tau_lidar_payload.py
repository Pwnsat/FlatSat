#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# FlatSat LiDAR payload -- depth-frame reduction and CCSDS payload codec.
#
# The Tau LiDAR Camera (Onion / ESPROS epc660, 160x60, millimetres) streams
# depth frames over USB. This module reduces a frame to a compact set of
# spacecraft telemetry scalars and packs them into the exact wire layout the
# FlatSat OBC firmware expects (Firmware/lidar.cpp lidarIngestSummary()).
#
# Pure standard library only -- no numpy, no pyserial, no camera SDK -- so the
# reduction and codec run (and are unit-tested) with no hardware present. The
# live-camera path and CCSDS transport live in tau_lidar_bridge.py.
from __future__ import annotations

import struct
from dataclasses import dataclass

SPACECRAFT_ID = 0x01

# ESPROS epc660 usable window, millimetres (datasheet: ~0.1 m .. 4.5 m).
VALID_MIN_MM = 100
VALID_MAX_MM = 4500
FRAME_WIDTH = 160
FRAME_HEIGHT = 60

# No-return / out-of-window sentinel. Matches Firmware/lidar.h LIDAR_DIST_INVALID.
DIST_INVALID = 0xFFFF

# status bits -- match Firmware/lidar.h LIDAR_STATUS_*
STATUS_FRAME_VALID = 0x01
STATUS_ALL_INVALID = 0x02
STATUS_SATURATED = 0x04

# FrameType mirror (TauLidarCommon.frame.FrameType)
FRAME_TYPE_DISTANCE = 0
FRAME_TYPE_DISTANCE_GRAYSCALE = 1
FRAME_TYPE_DISTANCE_AMPLITUDE = 2


@dataclass
class LidarSummary:
    """Reduced depth-frame summary. Mirrors lidar_summary_t in Firmware/lidar.h."""

    frame_type: int = FRAME_TYPE_DISTANCE
    min_mm: int = DIST_INVALID
    max_mm: int = DIST_INVALID
    mean_mm: int = DIST_INVALID
    center_mm: int = DIST_INVALID
    valid_pct: int = 0
    amplitude: int = 0
    width: int = FRAME_WIDTH
    height: int = FRAME_HEIGHT
    frame_count: int = 0
    status: int = 0


def _clamp_u16(value):
    """Round to an unsigned 16-bit range; None maps to the invalid sentinel."""
    if value is None:
        return DIST_INVALID
    value = int(round(value))
    if value < 0:
        return 0
    if value > 0xFFFF:
        return 0xFFFF
    return value


def reduce_frame(
    depth,
    width,
    height,
    *,
    amplitude=None,
    frame_type=FRAME_TYPE_DISTANCE,
    frame_count=0,
    valid_min_mm=VALID_MIN_MM,
    valid_max_mm=VALID_MAX_MM,
    amplitude_floor=0,
):
    """Reduce a row-major depth frame to a :class:`LidarSummary`.

    ``depth`` is a flat sequence (list / tuple / array / numpy array) of
    ``width * height`` per-pixel distances in millimetres. ``amplitude`` is an
    optional matching sequence of per-pixel return amplitude; pixels below
    ``amplitude_floor`` are treated as invalid.

    Invalid / no-return pixels are those outside ``[valid_min_mm, valid_max_mm]``
    -- the epc660 encodes no-return as 0 or a large sentinel value, *not* NaN,
    so masking is by physical window (NaN is also rejected defensively).
    """
    n = width * height
    if len(depth) < n:
        raise ValueError(
            "depth frame shorter than width*height (%d < %d)" % (len(depth), n)
        )

    valid = []
    saturated = 0
    for i in range(n):
        d = depth[i]
        # NaN-safe: (d != d) is True only for NaN.
        if d != d:
            continue
        if (
            amplitude is not None
            and amplitude_floor
            and i < len(amplitude)
            and amplitude[i] < amplitude_floor
        ):
            continue
        if d <= 0:
            continue
        if d < valid_min_mm or d > valid_max_mm:
            if d >= valid_max_mm:
                saturated += 1
            continue
        valid.append(d)

    summary = LidarSummary(
        frame_type=frame_type,
        width=width,
        height=height,
        frame_count=frame_count & 0xFFFFFFFF,
    )

    if valid:
        summary.min_mm = _clamp_u16(min(valid))
        summary.max_mm = _clamp_u16(max(valid))
        summary.mean_mm = _clamp_u16(sum(valid) / len(valid))

        center_index = (height // 2) * width + (width // 2)
        center = depth[center_index] if center_index < len(depth) else None
        if (
            center is not None
            and center == center
            and valid_min_mm <= center <= valid_max_mm
        ):
            summary.center_mm = _clamp_u16(center)
        else:
            summary.center_mm = DIST_INVALID

        summary.valid_pct = int(round(100.0 * len(valid) / n))
        summary.status = STATUS_FRAME_VALID
        if saturated * 2 > n:
            summary.status |= STATUS_SATURATED
    else:
        summary.status = STATUS_ALL_INVALID
        summary.valid_pct = 0

    if amplitude is not None:
        amps = [a for a in amplitude[:n] if a and a == a]
        if amps:
            summary.amplitude = _clamp_u16(sum(amps) / len(amps))

    return summary


# Summary wire block after SPACECRAFT_ID (little-endian). '<' forces standard
# sizes and no alignment padding, so byte offsets match Firmware/lidar.cpp:
#   B  frame_type
#   H  min_mm  H max_mm  H mean_mm  H center_mm
#   B  valid_pct
#   H  amplitude
#   H  width   H height
#   I  frame_count
#   B  status
_SUMMARY_STRUCT = struct.Struct("<BHHHHBHHHIB")
SUMMARY_WIRE_LEN = _SUMMARY_STRUCT.size  # 21


def encode_summary(summary):
    """Encode a :class:`LidarSummary` to its 21-byte wire block (no SPACECRAFT_ID)."""
    return _SUMMARY_STRUCT.pack(
        summary.frame_type & 0xFF,
        summary.min_mm & 0xFFFF,
        summary.max_mm & 0xFFFF,
        summary.mean_mm & 0xFFFF,
        summary.center_mm & 0xFFFF,
        summary.valid_pct & 0xFF,
        summary.amplitude & 0xFFFF,
        summary.width & 0xFFFF,
        summary.height & 0xFFFF,
        summary.frame_count & 0xFFFFFFFF,
        summary.status & 0xFF,
    )


def decode_summary(block):
    """Decode a 21-byte wire block (no SPACECRAFT_ID) to a :class:`LidarSummary`."""
    if len(block) < SUMMARY_WIRE_LEN:
        raise ValueError(
            "summary block too short: %d < %d" % (len(block), SUMMARY_WIRE_LEN)
        )
    (ft, mn, mx, me, ce, vp, amp, w, h, fc, st) = _SUMMARY_STRUCT.unpack_from(block, 0)
    return LidarSummary(
        frame_type=ft,
        min_mm=mn,
        max_mm=mx,
        mean_mm=me,
        center_mm=ce,
        valid_pct=vp,
        amplitude=amp,
        width=w,
        height=h,
        frame_count=fc,
        status=st,
    )


def build_lidar_payload(summary, spacecraft_id=SPACECRAFT_ID):
    """Full TC data field: ``SPACECRAFT_ID`` + summary block.

    This is the ``data`` handed to the FlatSat CCSDS builder for
    ``SPP_APID_TC_SET_LIDAR_FRAME``.
    """
    return bytes([spacecraft_id & 0xFF]) + encode_summary(summary)


def parse_lidar_payload(payload):
    """Inverse of :func:`build_lidar_payload` -> ``(spacecraft_id, LidarSummary)``."""
    if len(payload) < 1 + SUMMARY_WIRE_LEN:
        raise ValueError("lidar payload too short")
    return payload[0], decode_summary(payload[1:])


# Canned spoofing scenarios for the payload-data-spoofing attack (Attacks/08).
# Each is a plausible-but-forged scene the OBC will accept and republish.
SPOOF_PRESETS = {
    # A phantom obstacle inches from the sensor.
    "collision": dict(min_mm=150, mean_mm=350, max_mm=2000, center_mm=180,
                      valid_pct=95, amplitude=800, status=STATUS_FRAME_VALID),
    # Everything reads far away -- "the path is clear".
    "clear": dict(min_mm=4400, mean_mm=4450, max_mm=4490, center_mm=4450,
                  valid_pct=100, amplitude=600, status=STATUS_FRAME_VALID),
    # A blinded sensor: every pixel a no-return.
    "blind": dict(min_mm=DIST_INVALID, mean_mm=DIST_INVALID, max_mm=DIST_INVALID,
                  center_mm=DIST_INVALID, valid_pct=0, amplitude=0,
                  status=STATUS_ALL_INVALID),
}


def spoof_summary(
    preset="collision",
    *,
    frame_type=FRAME_TYPE_DISTANCE_AMPLITUDE,
    frame_count=1,
    **overrides,
):
    """Build a canned :class:`LidarSummary` for the payload-spoofing attack.

    ``preset`` selects a scene from :data:`SPOOF_PRESETS`; ``overrides`` (keyed
    by ``LidarSummary`` field name, e.g. ``min_mm=200``) replace individual
    fields -- ``None`` values are ignored so CLI defaults pass through cleanly.
    """
    if preset not in SPOOF_PRESETS:
        raise ValueError(
            "unknown preset %r (have %s)" % (preset, ", ".join(SPOOF_PRESETS))
        )
    fields = dict(SPOOF_PRESETS[preset])
    fields.update({k: v for k, v in overrides.items() if v is not None})
    return LidarSummary(
        frame_type=frame_type,
        frame_count=frame_count,
        width=FRAME_WIDTH,
        height=FRAME_HEIGHT,
        **fields,
    )
