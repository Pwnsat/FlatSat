#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 00_recon_apid_enum_usb.py -- black-box APID enumeration over FlatSat's
# real USB CDC serial link (USBRadioLink, 921600 baud), instead of real RF.
# "Round 1" (USB) of this attack -- see 00_recon_apid_enum_rf.py in this
# same folder for the original RF version.
#
# Root cause / vulnerability class: same as the RF version -- finding #4
# (no rate-limiting on uplink reception) + #21 (recon APIDs
# respond without authentication) + #22 (no TC/TM type check). The firmware
# ALWAYS answers a structurally valid packet, even for an APID it doesn't
# recognize (ERROR TM, 0x009) -- that gives every probe a classification,
# not just the "hits".
#
# WHY THIS IS SIMPLER THAN THE RF VERSION: over USB there's no leakage to
# filter (no uplink bleeding into a downlink receiver -- it's a direct,
# full-duplex wired link), no TX/RX turnaround race, and no SNR to reason
# about. The only real signal needed is which APID comes back in the
# reply's SPP header -- that header is never encrypted (only the payload
# is), so classification works whether or not the reply payload itself
# decrypts cleanly.
#
# NOT YET VALIDATED ON REAL HARDWARE (see lib/flatsat_usb.py's own header
# for why) -- the mechanism (framing, encryption, port probe) is the same
# one PWNSAT-C3's own SerialTransport and usb_tc_send.py already use in
# production, but this specific script has not been run against a real
# FlatSat board in this session.

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from flatsat_usb import FlatSatUSB  # noqa: E402
from pwnsat_packets import APIDS, decode_packet  # noqa: E402

ERROR_TM_APID = 0x009

# Same reasoning as the RF version's PROBE_PAYLOAD: 4 bytes, non-zero, so
# BROADCAST_MSG (0x06) doesn't hit the finding #10 underflow (needs a
# 0-byte payload specifically -- that's attack 02, not this tool) and
# SET_BEACON_RATE (0x05) doesn't get interval=0 and flood the downlink
# (finding #18, hit twice by hand before this fix during the RF version's
# own development -- see that script's SAFETY NOTE).
PROBE_PAYLOAD = bytes([0x01, 0x01, 0x01, 0x01])


def probe_apid(fsat: FlatSatUSB, apid: int, *, seq: int, listen_s: float,
               retries: int) -> str:
    print(f"\n[*] Probing APID 0x{apid:03X} ({APIDS.get(apid, 'not in known list')})...")
    for attempt in range(1, retries + 1):
        if retries > 1:
            print(f"    [attempt {attempt}/{retries}]")
        _raw, _framed, packets = fsat.send_raw_tc(
            apid, PROBE_PAYLOAD, seq=seq + attempt - 1, listen_seconds=listen_s,
        )
        for raw in packets:
            try:
                pkt = decode_packet(raw)
            except ValueError as exc:
                print(f"    -> got {len(raw)} bytes, couldn't parse as SPP: {exc}")
                continue
            if pkt.apid == apid:
                print(f"    -> REAL RESPONSE (matches probed APID): "
                      f"APID 0x{pkt.apid:03X} ({pkt.apid_name}) seq={pkt.sequence_count}")
                return "real"
            if pkt.apid == ERROR_TM_APID:
                print(f"    -> unknown (ERROR TM): APID 0x{pkt.apid:03X}")
                return "error"
            print(f"    -> unrelated traffic (different APID -- background beacon, "
                  f"not this probe): APID 0x{pkt.apid:03X} ({pkt.apid_name})")
        if attempt < retries:
            print(f"    -> no matching response yet (attempt {attempt}/{retries}), retrying...")
    print("    -> no matching response after all retries (worth a closer look by "
          "hand, or one of the APIDs that never replies on success -- see 0x004/0x005)")
    return "no-reply"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--start", type=lambda x: int(x, 0), default=0x00,
                        help="first APID to probe (default 0x00)")
    parser.add_argument("--end", type=lambda x: int(x, 0), default=0x14,
                        help="last APID to probe, inclusive (default 0x14 -- "
                             "covers every named APID in pwnsat_tools/spp_tools.py)")
    parser.add_argument("--skip", type=lambda x: int(x, 0), nargs="*", default=[],
                        metavar="APID",
                        help="APID(s) to exclude, e.g. --skip 2 6 to avoid "
                             "RESETC/the fuzzing crash")
    parser.add_argument("--listen-seconds", type=float, default=1.0,
                        help="how long to wait after each probe before checking "
                             "for a reply (default 1.0s)")
    parser.add_argument("--retries", type=int, default=2,
                        help="attempts per APID before giving up (default 2)")
    parser.add_argument("--seq", type=int, default=1, help="starting SPP sequence count")
    parser.add_argument("--port", default=None,
                        help="serial port for the USBRadioLink (default: autodetect)")
    parser.add_argument("--no-encrypt", action="store_true",
                        help="send probes in the clear instead of AES-128-ECB "
                             "(default: encrypted, matching the firmware's default)")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    skip = set(args.skip)
    targets = [a for a in range(args.start, args.end + 1) if a not in skip]

    print("=" * 66)
    print(f"PWNSAT APID enumeration (USB) -- probing {len(targets)} APID(s) "
          f"(0x{args.start:02X}-0x{args.end:02X}), skip={sorted(skip)}")
    print("Channel: FlatSat's real USBRadioLink CDC serial link, 921600 baud -- "
          "no RF hardware needed.")
    print("=" * 66)

    with FlatSatUSB(port=args.port, encrypt=not args.no_encrypt,
                    verbose=not args.quiet) as fsat:
        results: dict[int, str] = {}
        for i, apid in enumerate(targets):
            results[apid] = probe_apid(
                fsat, apid, seq=args.seq + i * args.retries,
                listen_s=args.listen_seconds, retries=args.retries,
            )
            time.sleep(0.2)

    real = {a for a, r in results.items() if r == "real"}
    errored = {a for a, r in results.items() if r == "error"}
    no_reply = {a for a, r in results.items() if r == "no-reply"}

    print("\n" + "=" * 66)
    print("SUMMARY")
    print("=" * 66)
    if real:
        print("Real, implemented commands found:")
        for apid in sorted(real):
            print(f"  0x{apid:03X}  {APIDS.get(apid, '?')}")
    if errored:
        print("Valid APID range, but not implemented (got ERROR TM back):")
        print("  " + ", ".join(f"0x{a:03X}" for a in sorted(errored)))
    if no_reply:
        print("No matching response (RF noise doesn't apply over USB -- likely "
              "one of the commands that never replies on success, e.g. "
              "SET_THRUSTER/SET_BEACON_RATE, or worth a closer look by hand):")
        print("  " + ", ".join(f"0x{a:03X}" for a in sorted(no_reply)))
    print(f"\n[*] Sweep complete -- {len(real)} real command(s) out of {len(targets)} probed.")


if __name__ == "__main__":
    main()
