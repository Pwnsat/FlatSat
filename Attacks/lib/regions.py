#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# ISM region selection for FlatSat attack scripts. Mirrors
# Firmware/regions.h -- if you build the firmware for EU868, set
# FLATSAT_REGION=eu868 in the environment so this library's TX/RX
# constants match the firmware's actual center frequencies.
#
# Falls back to us915 (918/916 MHz), the historical hardcoded pair,
# so anyone running with no env set gets exactly the previous behavior.

from __future__ import annotations

import os

# Same uplink/downlink split as Firmware/regions.h -- +2 MHz for every
# region except EU433, which is constrained to the strict CEPT ISM
# 433.05-434.79 MHz window (only ~1.74 MHz wide) so it uses a +1 MHz
# split on half-MHz boundaries to fit a 250 kHz channel BW cleanly
# in-band on both sides. Keep this table in sync when tuning any
# preset or adding a region.
REGIONS = {
    "us915": {"uplink_hz": 918_000_000, "downlink_hz": 916_000_000},
    "eu868": {"uplink_hz": 869_000_000, "downlink_hz": 867_000_000},
    "eu433": {"uplink_hz": 434_500_000, "downlink_hz": 433_500_000},
    "as923": {"uplink_hz": 924_000_000, "downlink_hz": 922_000_000},
}

DEFAULT_REGION = "us915"


def current_region() -> str:
    r = os.environ.get("FLATSAT_REGION", DEFAULT_REGION).lower()
    if r not in REGIONS:
        raise ValueError(
            f"FLATSAT_REGION={r!r} unknown; valid: {sorted(REGIONS)}"
        )
    return r


REGION = current_region()
UPLINK_FREQ_HZ = REGIONS[REGION]["uplink_hz"]
DOWNLINK_FREQ_HZ = REGIONS[REGION]["downlink_hz"]
UPLINK_FREQ_MHZ = UPLINK_FREQ_HZ / 1_000_000
DOWNLINK_FREQ_MHZ = DOWNLINK_FREQ_HZ / 1_000_000
