#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Hardware-free tests for the FlatSat LiDAR payload reduction + CCSDS codec.
# Pure standard library so they run in the CI gate (python:3.12-slim, no numpy,
# no pyserial, no camera SDK).
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tau_lidar_payload import (  # noqa: E402
    DIST_INVALID,
    FRAME_HEIGHT,
    FRAME_WIDTH,
    SPOOF_PRESETS,
    STATUS_ALL_INVALID,
    STATUS_FRAME_VALID,
    STATUS_SATURATED,
    SUMMARY_WIRE_LEN,
    LidarSummary,
    build_lidar_payload,
    decode_summary,
    encode_summary,
    parse_lidar_payload,
    reduce_frame,
    spoof_summary,
)


def _uniform_frame(width, height, distance_mm):
    return [float(distance_mm)] * (width * height)


def test_wire_length_is_21():
    # Firmware/lidar.h LIDAR_SUMMARY_WIRE_LEN must equal this.
    assert SUMMARY_WIRE_LEN == 21


def test_summary_roundtrip():
    s = LidarSummary(
        frame_type=2,
        min_mm=712,
        max_mm=2200,
        mean_mm=1801,
        center_mm=705,
        valid_pct=93,
        amplitude=400,
        width=160,
        height=60,
        frame_count=123456,
        status=STATUS_FRAME_VALID,
    )
    back = decode_summary(encode_summary(s))
    assert back == s


def test_payload_roundtrip_with_spacecraft_id():
    s = LidarSummary(min_mm=100, max_mm=4500, mean_mm=2000, center_mm=1999,
                     valid_pct=100, width=160, height=60, status=STATUS_FRAME_VALID)
    payload = build_lidar_payload(s)
    assert len(payload) == 1 + SUMMARY_WIRE_LEN
    assert payload[0] == 0x01  # SPACECRAFT_ID
    sc_id, back = parse_lidar_payload(payload)
    assert sc_id == 0x01
    assert back == s


def test_wire_byte_offsets_match_firmware():
    # Exact byte layout the firmware reads in lidarIngestSummary():
    #   [0] frameType, [1..2] min, [3..4] max, [5..6] mean, [7..8] center,
    #   [9] validPct, [10..11] amplitude, [12..13] width, [14..15] height,
    #   [16..19] frameCount, [20] status  (all little-endian).
    s = LidarSummary(
        frame_type=2, min_mm=0x0111, max_mm=0x0222, mean_mm=0x0333,
        center_mm=0x0444, valid_pct=0x5A, amplitude=0x0666, width=160,
        height=60, frame_count=0x0A0B0C0D, status=0x05,
    )
    block = encode_summary(s)
    assert block[0] == 2
    assert struct.unpack_from("<H", block, 1)[0] == 0x0111
    assert struct.unpack_from("<H", block, 3)[0] == 0x0222
    assert struct.unpack_from("<H", block, 5)[0] == 0x0333
    assert struct.unpack_from("<H", block, 7)[0] == 0x0444
    assert block[9] == 0x5A
    assert struct.unpack_from("<H", block, 10)[0] == 0x0666
    assert struct.unpack_from("<H", block, 12)[0] == 160
    assert struct.unpack_from("<H", block, 14)[0] == 60
    assert struct.unpack_from("<I", block, 16)[0] == 0x0A0B0C0D
    assert block[20] == 0x05


def test_reduce_uniform_frame():
    depth = _uniform_frame(FRAME_WIDTH, FRAME_HEIGHT, 2000)
    s = reduce_frame(depth, FRAME_WIDTH, FRAME_HEIGHT)
    assert s.min_mm == 2000
    assert s.max_mm == 2000
    assert s.mean_mm == 2000
    assert s.center_mm == 2000
    assert s.valid_pct == 100
    assert s.status & STATUS_FRAME_VALID
    assert not s.status & STATUS_ALL_INVALID


def test_reduce_masks_invalid_pixels():
    # Half the frame is no-return (0.0), half is a valid 1500 mm return.
    n = FRAME_WIDTH * FRAME_HEIGHT
    depth = [0.0] * (n // 2) + [1500.0] * (n - n // 2)
    s = reduce_frame(depth, FRAME_WIDTH, FRAME_HEIGHT)
    assert s.min_mm == 1500
    assert s.max_mm == 1500
    assert s.mean_mm == 1500
    assert 40 <= s.valid_pct <= 60
    assert s.status & STATUS_FRAME_VALID


def test_reduce_all_invalid_frame():
    depth = _uniform_frame(FRAME_WIDTH, FRAME_HEIGHT, 0)  # all no-return
    s = reduce_frame(depth, FRAME_WIDTH, FRAME_HEIGHT)
    assert s.min_mm == DIST_INVALID
    assert s.mean_mm == DIST_INVALID
    assert s.center_mm == DIST_INVALID
    assert s.valid_pct == 0
    assert s.status & STATUS_ALL_INVALID
    assert not s.status & STATUS_FRAME_VALID


def test_reduce_out_of_range_and_nan_excluded():
    n = FRAME_WIDTH * FRAME_HEIGHT
    depth = [2000.0] * n
    depth[0] = 50.0  # below VALID_MIN_MM -> excluded
    depth[1] = 9000.0  # above VALID_MAX_MM -> excluded (and saturated)
    depth[2] = float("nan")  # NaN -> excluded
    s = reduce_frame(depth, FRAME_WIDTH, FRAME_HEIGHT)
    assert s.min_mm == 2000
    assert s.max_mm == 2000
    # 3 of 9600 pixels excluded -> 99.97% valid, rounds to 100.
    assert s.valid_pct in (99, 100)


def test_reduce_saturated_flag():
    # Most of the frame reads at/over max range -> SATURATED set.
    n = FRAME_WIDTH * FRAME_HEIGHT
    depth = [9000.0] * n
    depth[0] = 2000.0  # one valid pixel so it is not ALL_INVALID
    s = reduce_frame(depth, FRAME_WIDTH, FRAME_HEIGHT)
    assert s.status & STATUS_FRAME_VALID
    assert s.status & STATUS_SATURATED


def test_reduce_amplitude_floor_masks_low_confidence():
    n = FRAME_WIDTH * FRAME_HEIGHT
    depth = [1500.0] * n
    amp = [500] * n
    amp[: n // 2] = [10] * (n // 2)  # low amplitude -> masked out
    s = reduce_frame(depth, FRAME_WIDTH, FRAME_HEIGHT, amplitude=amp,
                     amplitude_floor=100)
    assert s.min_mm == 1500
    assert 40 <= s.valid_pct <= 60
    assert s.amplitude > 0


def test_reduce_rejects_short_frame():
    try:
        reduce_frame([1.0, 2.0], FRAME_WIDTH, FRAME_HEIGHT)
    except ValueError:
        return
    raise AssertionError("expected ValueError for short frame")


def test_spoof_presets_roundtrip_and_wire_valid():
    # Every attack preset (Attacks/08) must encode to a valid 22-byte payload
    # that round-trips through the firmware-shared codec unchanged.
    for name in SPOOF_PRESETS:
        s = spoof_summary(name)
        payload = build_lidar_payload(s)
        assert len(payload) == 1 + SUMMARY_WIRE_LEN
        sc_id, back = parse_lidar_payload(payload)
        assert sc_id == 0x01
        assert back == s
    # Scene semantics.
    assert spoof_summary("collision").min_mm < 500
    assert spoof_summary("clear").min_mm > 4000
    assert spoof_summary("blind").status & STATUS_ALL_INVALID
    assert spoof_summary("blind").min_mm == DIST_INVALID


def test_spoof_override_applies():
    s = spoof_summary("clear", min_mm=200, center_mm=None)
    assert s.min_mm == 200  # override wins
    assert s.center_mm == SPOOF_PRESETS["clear"]["center_mm"]  # None ignored


def test_spoof_unknown_preset_rejected():
    try:
        spoof_summary("nope")
    except ValueError:
        return
    raise AssertionError("expected ValueError for unknown preset")


def test_simulated_scene_end_to_end():
    # Import the bridge's synthesizer and run the full reduce->encode->decode
    # path, proving the pipeline works with no camera and no board.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from tau_lidar_bridge import simulate_frame

    depth, amp = simulate_frame(FRAME_WIDTH, FRAME_HEIGHT, frame_count=0)
    s = reduce_frame(depth, FRAME_WIDTH, FRAME_HEIGHT, amplitude=amp, frame_count=7)
    # Scene has a ~700 mm object and a ~1800-2200 mm wall.
    assert s.status & STATUS_FRAME_VALID
    assert 600 <= s.min_mm <= 800
    assert 1800 <= s.max_mm <= 2300
    assert s.frame_count == 7
    # Round-trips through the wire codec unchanged.
    sc_id, back = parse_lidar_payload(build_lidar_payload(s))
    assert sc_id == 0x01
    assert back == s
