#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# pwnsat_packets.py
#
# Thin bootstrap that puts PWNSAT-C3's pwnsat_tools/ on sys.path and
# re-exports the packet-building functions attack scripts need, instead of
# duplicating any SPP/CCSDS or AES-ECB logic here (usb_tc_send.py's
# build_wire_payload/build_logical_payload + spp_tools.py's build_tc).
#
# Deliberately does NOT import backend/command_registry.py, which is tied to
# the FastAPI app's `settings`; this goes straight to pwnsat_tools instead.

import sys
from argparse import Namespace
from pathlib import Path

_PWNSAT_TOOLS = (
    Path(__file__).resolve().parents[3]
    / "PWNSAT-C3" / "pwnsat_tools"
)
if str(_PWNSAT_TOOLS) not in sys.path:
    sys.path.insert(0, str(_PWNSAT_TOOLS))

from spp_tools import APIDS, SEC_HEADER_LEN, build_tc, build_tm, decode_packet  # noqa: E402,F401
from pwnsat_crypto import AES_KEY, decrypt_payload, encrypt_payload  # noqa: E402,F401
from usb_tc_send import APID_NAMES, build_logical_payload, build_wire_payload  # noqa: E402,F401

# usb_tc_send.build_logical_payload/build_wire_payload read their arguments
# off an argparse.Namespace (args.command, args.thruster_id, ...) rather
# than a plain dict -- this mirrors command_registry.py's DEFAULT_ARGS so an
# attack script only has to pass the handful of fields that actually matter
# for its one APID, not the full set every command type could use.
DEFAULT_ARGS = {
    "payload_hex": None,
    "encrypt": "on",
    "thruster_id": 0,
    "power": 80,
    "seconds": 1,
    "frequency": 0x0394,
    "message": "Pwnsat",
    "mission_mode": 1,
    "aes_mode": 0,
    "debug_mode": 0,
    "gs_comm_mode": 0,
    "handshake": "start",
    "challenge": None,
    "auth_key": 0xC0DEFACE,
    "offset": 0,
    "read_length": 32,
    "window_id": 0xA5,
    "unlock_tag": 0xC35A,
}


def build_command_packet(command: str, seq: int = 1, encrypt: bool = True,
                         **overrides) -> bytes:
    """Build one raw SPP telecommand (primary header + payload, encrypted
    with the known AES key unless encrypt=False) for `command` -- one of
    APID_NAMES's keys: ping, reset, fw, thruster, beacon, broadcast, flash,
    aes, flash-read, status, mode, nav, payload-status, debug, gs-mode,
    gs-auth, gs-status.

    This is the raw SPP bytes an attack script hands straight to
    pwnsat_lora_tx.transmit_packet() -- no USB 0xAA framing (that's a
    serial-transport-only concept, see usb_tc_send.py's frame_usb; LoRa
    carries the raw SPP packet as its payload directly, confirmed by
    gradio/pwnsat_lora_rx.py's ZMQ sink publishing lora_rx's output
    unwrapped).

    Example -- RESETC, no payload, encrypted:
        build_command_packet("reset", seq=1)

    Example -- SET_THRUSTER, thruster 0 to power 200, encrypted:
        build_command_packet("thruster", seq=1, thruster_id=0, power=200)
    """
    if command not in APID_NAMES:
        raise ValueError(f"unknown command {command!r} -- see APID_NAMES")

    merged = dict(DEFAULT_ARGS)
    merged.update(overrides)
    merged["command"] = command
    merged["encrypt"] = "on" if encrypt else "off"
    args = Namespace(**merged)

    payload = build_wire_payload(args)
    return build_tc(APID_NAMES[command], payload, seq)
