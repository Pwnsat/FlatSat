#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# CatSniffer v2 (Electronic Cats, SX1262 onboard) as a dedicated, always-on
# LoRa downlink listener.
#
# Why this exists: a single HackRF cannot reliably catch the FlatSat's
# downlink reply -- it answers in ~11ms, faster than a half-duplex SDR can
# close an uplink `hackrf_transfer -t` and reopen `hackrf_transfer -r`
# (100ms+ of USB/device-reinit overhead, a deterministic hardware limit, not
# RF noise). A second dedicated radio removes the race: this keeps the
# CatSniffer in RX continuously while HackRF (pwnsat_lora_tx.py) stays
# TX-only, so there's no window to miss.
#
# The CatSniffer already had Electronic Cats' "LoRa Sniffer CLI 0.1" firmware
# flashed -- no firmware work needed; this only drives its serial CLI
# (115200 8N1). Its defaults (SF7, CR 4/5, sync word 0x12, preamble 8)
# matched New-firmware/rdownlink.h out of the box; only frequency
# (915.0 -> 916.0) and bandwidth (125 -> 250, index 8) needed changing.

from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass
from typing import Optional

import serial
import serial.tools.list_ports

CATSNIFFER_BAUD = 115200

# Mirrors New-firmware/rdownlink.h's downlink radio config exactly.
DOWNLINK_FREQ_MHZ = 916.0
DOWNLINK_BW_INDEX = 8  # this firmware's set_bw takes a table INDEX, not
                       # kHz directly -- confirmed by hand: index 8 -> 250 kHz
DOWNLINK_SF = 7
DOWNLINK_CR = 5  # "4/5" -- already this firmware's own default

_HEX_LINE_RE = re.compile(r"^(?:[0-9A-Fa-f]{2} )+[0-9A-Fa-f]{2}$")
# Anchored on the label text itself -- a bare `(-?\d+...)` search on the
# raw line matches the "1262" in the "[SX1262]" prefix that starts every
# line this firmware prints, well before it reaches the real value.
_RSSI_RE = re.compile(r"RSSI:\s*(-?\d+(?:\.\d+)?)")
_SNR_RE = re.compile(r"SNR:\s*(-?\d+(?:\.\d+)?)")


@dataclass
class CapturedFrame:
    raw: bytes
    rssi_dbm: float
    snr_db: float
    t_captured: float


def find_catsniffer_port() -> Optional[str]:
    """Autodetects the CatSniffer by USB descriptor (manufacturer
    "Electronic Cats", product "Cat Sniffer") -- same reasoning as
    port_detect.py's approach for the FlatSat's own USB links: don't
    hardcode a device path that can shift across reconnects."""
    for p in serial.tools.list_ports.comports():
        manufacturer = (p.manufacturer or "").lower()
        product = (p.product or "").lower()
        if "electronic cats" in manufacturer or "cat sniffer" in product:
            return p.device
    return None


class CatSnifferRX:
    """Drives an Electronic Cats CatSniffer v2 (LoRa Sniffer CLI
    firmware) as a continuous, dedicated LoRa RX. See module docstring
    for why this exists instead of switching one HackRF between TX/RX."""

    def __init__(self, port: Optional[str] = None, *,
                freq_mhz: float = DOWNLINK_FREQ_MHZ,
                bw_index: int = DOWNLINK_BW_INDEX,
                sf: int = DOWNLINK_SF, cr: int = DOWNLINK_CR,
                verbose: bool = True):
        if port is None:
            port = find_catsniffer_port()
            if port is None:
                raise RuntimeError(
                    "CatSniffer not found -- is it plugged in? "
                    "(looked for a USB serial device reporting "
                    "manufacturer 'Electronic Cats' / product 'Cat Sniffer')"
                )
        self.verbose = verbose
        self._ser = serial.Serial(port, CATSNIFFER_BAUD, timeout=0.2)
        # A fresh USB-CDC open needs real settle time before the device's
        # own UART/CLI is actually ready -- confirmed by hand (2026-07-17)
        # that the very first command sent right after opening can arrive
        # while the device is still finishing enumeration and gets
        # silently mangled (a `set_freq 916.0` came back "Command not
        # found", the frequency stayed at its power-on default, and the
        # whole sweep ran against the wrong frequency with no visible
        # error until someone actually read the config back). A bare
        # newline first, discarded, flushes out that dead byte or two
        # before anything that matters gets sent.
        time.sleep(1.0)
        self._ser.reset_input_buffer()
        self._cmd("", wait_s=0.3)
        if self.verbose:
            print(f"[CatSniffer] using {port}")
        self._configure(freq_mhz, bw_index, sf, cr)

        self._frames: list[CapturedFrame] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._buf = ""
        self._thread = threading.Thread(target=self._reader_loop, daemon=True)
        self._started = False

    def _cmd(self, line: str, wait_s: float = 0.4) -> str:
        self._ser.write((line + "\n").encode("ascii"))
        time.sleep(wait_s)
        reply = self._ser.read(2000).decode("ascii", errors="replace")
        if self.verbose:
            print(f"[CatSniffer] {line} -> {reply.strip()!r}")
        return reply

    def _read_config(self) -> dict:
        reply = self._cmd("get_config", wait_s=0.4)
        values: dict = {}
        for line in reply.splitlines():
            m = re.match(r"\s*Frequency\s*=\s*([\d.]+)\s*MHz", line)
            if m:
                values["freq_mhz"] = float(m.group(1))
            m = re.match(r"\s*Bandwidth\s*=\s*(\d+)\s*kHz", line)
            if m:
                values["bw_khz"] = int(m.group(1))
            m = re.match(r"\s*Spreading Factor\s*=\s*(\d+)", line)
            if m:
                values["sf"] = int(m.group(1))
        return values

    def _configure(self, freq_mhz: float, bw_index: int, sf: int, cr: int,
                   *, _retried: bool = False) -> None:
        self._cmd(f"set_freq {freq_mhz}")
        self._cmd(f"set_bw {bw_index}")
        self._cmd(f"set_sf {sf}")
        self._cmd(f"set_cr {cr}")

        # Don't trust the per-command ack alone -- confirmed by hand that
        # a mangled command can come back with an unrelated-looking error
        # ("Command not found") while every command AFTER it acks clean,
        # so a sweep can run start-to-finish tuned to the wrong frequency
        # with no obvious signal anything went wrong. Read the config
        # back and verify it actually stuck.
        actual = self._read_config()
        bw_khz_expected = {0: 7.8, 1: 10.4, 2: 15.6, 3: 20.8, 4: 31.25,
                           5: 41.7, 6: 62.5, 7: 125, 8: 250}.get(bw_index)
        mismatches = []
        if actual.get("freq_mhz") is None or abs(actual["freq_mhz"] - freq_mhz) > 0.05:
            mismatches.append(f"freq: wanted {freq_mhz}MHz, got {actual.get('freq_mhz')}MHz")
        if bw_khz_expected is not None and actual.get("bw_khz") != int(bw_khz_expected):
            mismatches.append(f"bw: wanted {bw_khz_expected}kHz, got {actual.get('bw_khz')}kHz")
        if actual.get("sf") != sf:
            mismatches.append(f"sf: wanted {sf}, got {actual.get('sf')}")

        if mismatches:
            if _retried:
                raise RuntimeError(
                    "CatSniffer config didn't stick after a retry -- "
                    f"{'; '.join(mismatches)}. A sweep run against the "
                    "wrong PHY config would silently catch nothing; "
                    "not proceeding. Try unplugging/replugging the "
                    "CatSniffer and running again."
                )
            if self.verbose:
                print(f"[CatSniffer] config verify failed ({'; '.join(mismatches)}) "
                      f"-- retrying once")
            time.sleep(0.3)
            self._configure(freq_mhz, bw_index, sf, cr, _retried=True)
        elif self.verbose:
            print(f"[CatSniffer] config verified: {actual}")

    def start(self) -> None:
        """Puts the CatSniffer into continuous RX and starts the
        background reader thread. Call this ONCE per session -- unlike
        the HackRF TX path, this never needs to stop/restart between
        probes; that's the whole point."""
        if self._started:
            return
        self._cmd("set_rx")
        self._thread.start()
        self._started = True

    def _reader_loop(self) -> None:
        while not self._stop.is_set():
            n = self._ser.in_waiting
            if not n:
                # Short poll interval -- this thread competes with the
                # main thread's CPU-bound LoRa baseband rendering
                # (pwnsat_lora_tx.py) for the GIL; a longer sleep here
                # made backlog buildup (see take_since()'s docstring)
                # measurably worse in practice.
                time.sleep(0.005)
                continue
            chunk = self._ser.read(n).decode("ascii", errors="replace")
            self._buf += chunk
            self._drain_complete_blocks()

    def _drain_complete_blocks(self) -> None:
        while True:
            start = self._buf.find("[SX1262] Received packet!")
            if start == -1:
                if len(self._buf) > 8000:
                    self._buf = self._buf[-4000:]
                return
            end = self._buf.find("[SX1262] SNR:", start)
            if end == -1:
                return
            line_end = self._buf.find("\n", end)
            if line_end == -1:
                return
            block = self._buf[start:line_end + 1]
            self._buf = self._buf[line_end + 1:]
            frame = self._parse_block(block)
            if frame is not None:
                with self._lock:
                    self._frames.append(frame)
                if self.verbose:
                    print(f"[CatSniffer] captured {len(frame.raw)} bytes, "
                          f"RSSI={frame.rssi_dbm:.1f}dBm SNR={frame.snr_db:.1f}dB")

    @staticmethod
    def _parse_block(block: str) -> Optional["CapturedFrame"]:
        hex_bytes: list[str] = []
        rssi = None
        snr = None
        for raw_line in block.splitlines():
            line = raw_line.strip()
            if _HEX_LINE_RE.match(line):
                hex_bytes.extend(line.split())
            elif line.startswith("[SX1262] RSSI:"):
                m = _RSSI_RE.search(line)
                if m:
                    rssi = float(m.group(1))
            elif line.startswith("[SX1262] SNR:"):
                m = _SNR_RE.search(line)
                if m:
                    snr = float(m.group(1))
        if not hex_bytes or rssi is None or snr is None:
            return None
        try:
            raw = bytes(int(b, 16) for b in hex_bytes)
        except ValueError:
            return None
        return CapturedFrame(raw=raw, rssi_dbm=rssi, snr_db=snr, t_captured=time.time())

    def take_since(self, t0: float) -> list[CapturedFrame]:
        """Every frame captured at or after t0 -- REMOVED from the
        internal buffer so a later probe's window can never see it
        again. Normal usage: record time.time() right before
        transmit_packet(), then call this after a short wait -- since
        the CatSniffer never stops listening, there's no separate
        "start/stop capture" step per probe.

        Why "take" and not just "read": confirmed by hand (2026-07-17)
        that a plain non-destructive read here produces real
        duplicate-report bugs -- the reader thread
        can fall behind while the main thread is busy CPU-bound
        rendering a LoRa baseband (pwnsat_lora_tx.py), so a backlog of
        several already-buffered beacon frames gets parsed all at once,
        all stamped with nearly the same (late) `time.time()`. Left
        un-consumed, that whole backlog would satisfy `>= t0` for every
        subsequent probe's window until time finally moved past it,
        getting the exact same frame reported against several unrelated
        probes in a row."""
        with self._lock:
            matched = [f for f in self._frames if f.t_captured >= t0]
            if matched:
                self._frames = [f for f in self._frames if f.t_captured < t0]
            return matched

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=1)
        self._ser.close()
