#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# RTL-SDR as a dedicated, always-on LoRa downlink listener -- fallback for
# 00_recon_apid_enum when a CatSniffer isn't available.
#
# Why this exists: pwnsat_catsniffer_rx.py was built first (see its docstring
# for the TX/RX-turnaround diagnosis), but a CatSniffer isn't always on hand.
# PWNSAT-C3's own RTL-SDR is the other receive-capable radio usually
# available, so this borrows it for 00's RX (stop C3 first, they can't share
# it). A second dedicated radio removes the single-HackRF TX/RX turnaround
# race, since it never switches modes.
#
# Reuses PwnsatLoraRX (the same flowgraph 01_eavesdropping/pwnsat_lora_rx.py
# uses) instead of duplicating the SoapySDR/gain handling. Runs it
# continuously, publishing to a local loopback ZMQ address, with a SUB socket
# in this process to recover decoded frames.

from __future__ import annotations

import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import zmq

_EAVESDROPPING_DIR = Path(__file__).resolve().parents[1] / "01_eavesdropping"
if str(_EAVESDROPPING_DIR) not in sys.path:
    sys.path.insert(0, str(_EAVESDROPPING_DIR))

from pwnsat_lora_rx import PwnsatLoraRX  # noqa: E402

# Mirrors New-firmware/rdownlink.h's downlink radio config exactly --
# same values pwnsat_catsniffer_rx.py and pwnsat_lora_rx_capture.py use.
DOWNLINK_FREQ_HZ = 916_000_000
DOWNLINK_BW_HZ = 250_000
DOWNLINK_SF = 7


@dataclass
class CapturedFrame:
    raw: bytes
    t_captured: float


class RtlSdrRX:
    """Drives an RTL-SDR (via PwnsatLoraRX's live GNU Radio flowgraph) as
    a continuous, dedicated LoRa RX. Same take_since()-based API as
    CatSnifferRX so 00_recon_apid_enum.py can use either interchangeably.
    No RSSI/SNR here -- PwnsatLoraRX's ZMQ output is raw decoded bytes
    only, unlike the CatSniffer's own CLI which reports it per packet."""

    def __init__(self, *, frequency: int = DOWNLINK_FREQ_HZ,
                bandwidth: int = DOWNLINK_BW_HZ, sf: int = DOWNLINK_SF,
                rf_gain: int = 30, zmq_port: int = 0, verbose: bool = True):
        self.verbose = verbose
        if not zmq_port:
            zmq_port = _free_local_port()
        self._zmq_address = f"tcp://127.0.0.1:{zmq_port}"

        self._tb = PwnsatLoraRX(
            device_args="rtlsdr", frequency=frequency, bandwidth=bandwidth,
            zmq_address=self._zmq_address, spread_factor=sf, rf_gain=rf_gain,
        )

        self._ctx = zmq.Context()
        self._sub = self._ctx.socket(zmq.SUB)
        self._sub.connect(self._zmq_address)
        self._sub.setsockopt(zmq.SUBSCRIBE, b"")
        self._sub.setsockopt(zmq.RCVTIMEO, 100)

        self._frames: list[CapturedFrame] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._reader_loop, daemon=True)
        self._started = False

    def start(self) -> None:
        """Starts the RTL-SDR flowgraph and the background reader
        thread. Call ONCE per session -- it never needs to stop/restart
        between probes, that's the whole point of a dedicated RX."""
        if self._started:
            return
        self._tb.start()
        self._tb.flowgraph_started.wait(timeout=5)
        # ZMQ PUB/SUB "slow joiner" settle -- same reasoning as
        # pwnsat_lora_rx_capture.py's offline decode: give the SUB socket
        # time to finish connecting before anything meaningful publishes.
        time.sleep(0.5)
        self._thread.start()
        self._started = True
        if self.verbose:
            print(f"[RTL-SDR] listening at {DOWNLINK_FREQ_HZ/1e6:.2f}MHz "
                  f"via {self._zmq_address}")

    def _reader_loop(self) -> None:
        while not self._stop.is_set():
            try:
                raw = self._sub.recv()
            except zmq.Again:
                continue
            frame = CapturedFrame(raw=raw, t_captured=time.time())
            with self._lock:
                self._frames.append(frame)
            if self.verbose:
                print(f"[RTL-SDR] captured {len(raw)} bytes")

    def take_since(self, t0: float) -> list[CapturedFrame]:
        """Every frame captured at or after t0, removed from the
        internal buffer so a later probe's window can never see it
        again -- see pwnsat_catsniffer_rx.py's take_since() docstring
        for why this matters (a backlogged frame parsed late would
        otherwise get reported against multiple probes in a row)."""
        with self._lock:
            matched = [f for f in self._frames if f.t_captured >= t0]
            if matched:
                self._frames = [f for f in self._frames if f.t_captured < t0]
            return matched

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=1)
        self._tb.stop()
        self._tb.wait()
        self._sub.close(0)
        self._ctx.term()


def _free_local_port() -> int:
    import socket as _socket
    s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port
