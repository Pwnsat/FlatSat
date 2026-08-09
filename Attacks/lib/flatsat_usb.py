#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# flatsat_usb.py -- standalone USB transport for FlatSat's real USBRadioLink
# CDC serial link (921600 baud), for attack scripts that need to send a
# telecommand directly over USB instead of real RF (HackRF/RTL-SDR).
#
# Reuses this repo's own packet toolkit instead of re-deriving any
# SPP/CCSDS/AES-ECB byte layout here:
#   - spp_tools.py (pwnsat_tools/)   -> build_tc(), decode_packet()
#   - pwnsat_crypto.py               -> AES-128-ECB encrypt/decrypt
#   - usb_tc_send.py                 -> frame_usb() (0xAA 0x55 <len:2 BE>
#     <raw SPP>, the USBRadioLink wire framing) and iter_usb_sync_packets()
#     (re-sync + split a raw stream back into 0xAA-framed packets)
#   - pwnsat_packets.py (this lib/)  -> build_command_packet(), which builds
#     a byte-exact TC for every named command (ping, reset, thruster,
#     beacon, broadcast, aes, gs-mode, gs-auth, gs-status, ...)
#
# Port auto-detection: FlatSat exposes TWO USB CDC interfaces with the SAME
# serial-number string, and which one enumerates as ...fsat1 vs ...fsat3 is
# not stable across reconnects. This reimplements backend port_detect.py's
# probe-with-a-PING strategy locally (rather than importing it and pulling
# in FastAPI-adjacent backend.settings) -- same protocol, zero web-app
# coupling.

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Optional

import serial
import serial.tools.list_ports

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent / "PWNSAT-C3" / "pwnsat_tools"))

from pwnsat_packets import build_command_packet, decode_packet, decrypt_payload  # noqa: E402
from spp_tools import build_tc  # noqa: E402
from pwnsat_crypto import encrypt_payload  # noqa: E402
from usb_tc_send import APID_NAMES, frame_usb, iter_usb_sync_packets  # noqa: E402

PROBE_BAUD = 921600
PROBE_TIMEOUT_S = 1.5
PROBE_READ_BYTES = 64
BINARY_SYNC_BYTE = 0xAA


def _candidate_ports() -> list[str]:
    return sorted(p.device for p in serial.tools.list_ports.comports())


def _build_ping_probe_frame() -> bytes:
    return frame_usb(build_command_packet("ping", seq=1, encrypt=False))


def _probe_port(port_name: str, probe_frame: bytes) -> bool:
    try:
        with serial.Serial(port_name, PROBE_BAUD, timeout=PROBE_TIMEOUT_S) as ser:
            ser.write(probe_frame)
            ser.flush()
            sample = ser.read(PROBE_READ_BYTES)
    except serial.SerialException:
        return False
    return bool(sample) and sample[0] == BINARY_SYNC_BYTE


def find_binary_link_port(verbose: bool = True) -> Optional[str]:
    """Same strategy as backend/transport/port_detect.py: probe every
    currently-enumerated serial port with an unencrypted PING and see which
    one answers with an 0xAA-framed response. Not filtered by name/VID/PID
    on purpose -- that's exactly what's unstable across reconnects."""
    probe_frame = _build_ping_probe_frame()
    for port in _candidate_ports():
        if verbose:
            print(f"    [*] probing {port} ...")
        if _probe_port(port, probe_frame):
            if verbose:
                print(f"    -> {port} answered a PING probe -- using it")
            return port
    return None


class FlatSatUSB:
    """Context-manager wrapper around FlatSat's real USBRadioLink CDC
    serial link. Unlike PWNCUBE's PwncubeUSB (which drives a menu-driven
    debug console over vendor-specific USB bulk endpoints), this talks
    FlatSat's real binary telecommand/telemetry protocol directly -- no
    console, no shell, just framed SPP packets over a standard serial port.

    Usage:
        with FlatSatUSB() as fsat:                    # auto-detects the port
            raw_spp, framed, replies = fsat.send_tc("thruster", seq=1,
                                                     thruster_id=0, power=255)
    """

    def __init__(self, port: Optional[str] = None, baud: int = PROBE_BAUD,
                 encrypt: bool = True, verbose: bool = True):
        self.port_name = port
        self.baud = baud
        self.encrypt = encrypt
        self.verbose = verbose
        self.ser: Optional[serial.Serial] = None

    def connect(self) -> None:
        if self.port_name is None:
            if self.verbose:
                print("[*] No --port given, auto-detecting FlatSat's binary USB link...")
            self.port_name = find_binary_link_port(verbose=self.verbose)
            if self.port_name is None:
                raise RuntimeError(
                    "FlatSat's binary USBRadioLink port not found -- not connected, "
                    "not powered, or genuinely not responding to a PING probe. "
                    "Pass --port explicitly if auto-detect keeps missing it."
                )
        if self.verbose:
            print(f"[*] Opening {self.port_name} @ {self.baud} baud...")
        self.ser = serial.Serial(self.port_name, self.baud, timeout=0.1)
        time.sleep(0.2)

    def close(self) -> None:
        if self.ser is not None:
            self.ser.close()
            self.ser = None

    def __enter__(self) -> "FlatSatUSB":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def send_tc(self, command: str, *, seq: int = 1, listen_seconds: float = 1.0,
                **overrides) -> tuple[bytes, bytes, list[bytes]]:
        """Builds the named command's raw SPP telecommand (see
        pwnsat_packets.build_command_packet for the full list of command
        names and overrides), frames it for the USB wire, sends it, and
        listens for `listen_seconds` for any 0xAA-framed reply packets.

        Returns (raw_spp, framed_bytes, [raw_spp_reply, ...]) -- replies is
        a list because a single read window can catch more than one frame
        (e.g. a queued periodic beacon arriving right after the real ACK).
        """
        if self.ser is None:
            raise RuntimeError("not connected -- call connect() or use as a context manager")

        raw_spp = build_command_packet(command, seq=seq, encrypt=self.encrypt, **overrides)
        framed = frame_usb(raw_spp)

        if self.verbose:
            print(f"[*] TX -> {command} (APID 0x{APID_NAMES[command]:02X})  "
                  f"seq={seq}  {len(framed)} bytes framed")
            print(f"    {framed.hex()}")

        self.ser.write(framed)
        self.ser.flush()

        deadline = time.time() + listen_seconds
        received = bytearray()
        while time.time() < deadline:
            chunk = self.ser.read(4096)
            if chunk:
                received.extend(chunk)

        packets, _trailing = iter_usb_sync_packets(bytes(received))
        if self.verbose:
            if packets:
                for i, raw in enumerate(packets, 1):
                    try:
                        pkt = decode_packet(raw)
                        print(f"    <- reply {i}: APID=0x{pkt.apid:03X} "
                              f"seq={pkt.sequence_count} ({len(raw)} bytes)")
                    except ValueError:
                        print(f"    <- reply {i}: {len(raw)} bytes, could not parse as SPP")
            else:
                print("    <- no reply captured in the listen window")

        return raw_spp, framed, packets

    def send_raw_tc(self, apid: int, payload: bytes, *, seq: int = 1,
                    listen_seconds: float = 1.0) -> tuple[bytes, bytes, list[bytes]]:
        """Same as send_tc(), but for an arbitrary numeric APID with a raw
        payload -- for black-box recon (attack 00) where the APID being
        probed may not be a known/named command at all. Encrypts the
        payload first unless self.encrypt is False, same as send_tc()."""
        if self.ser is None:
            raise RuntimeError("not connected -- call connect() or use as a context manager")

        wire_payload = encrypt_payload(payload) if self.encrypt else payload
        raw_spp = build_tc(apid, wire_payload, seq)
        framed = frame_usb(raw_spp)

        if self.verbose:
            print(f"[*] TX -> APID 0x{apid:03X}  seq={seq}  {len(framed)} bytes framed")
            print(f"    {framed.hex()}")

        self.ser.write(framed)
        self.ser.flush()

        deadline = time.time() + listen_seconds
        received = bytearray()
        while time.time() < deadline:
            chunk = self.ser.read(4096)
            if chunk:
                received.extend(chunk)

        packets, _trailing = iter_usb_sync_packets(bytes(received))
        if self.verbose:
            if packets:
                for i, raw in enumerate(packets, 1):
                    try:
                        pkt = decode_packet(raw)
                        print(f"    <- reply {i}: APID=0x{pkt.apid:03X} "
                              f"seq={pkt.sequence_count} ({len(raw)} bytes)")
                    except ValueError:
                        print(f"    <- reply {i}: {len(raw)} bytes, could not parse as SPP")
            else:
                print("    <- no reply captured in the listen window")

        return raw_spp, framed, packets

    def decode_reply_payload(self, raw_spp: bytes) -> bytes:
        """Decodes one reply packet's payload, decrypting it first if this
        connection is in encrypted mode (self.encrypt)."""
        pkt = decode_packet(raw_spp)
        if not pkt.data:
            return b""
        if self.encrypt:
            return decrypt_payload(pkt.data)
        return pkt.data
