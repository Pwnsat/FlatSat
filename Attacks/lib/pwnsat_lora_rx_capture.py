#!/usr/bin/env python3
# HackRF RX capture + offline LoRa decode -- built for the APID enumeration
# tool (attacks/00_recon_apid_enum), reusable by any tool that listens for a
# response on the SAME HackRF it also transmits with (e.g. attack 05's RX
# half). Mirror image of pwnsat_lora_tx.py: that shells out to
# hackrf_transfer -t; this shells out to hackrf_transfer -r, then decodes
# the capture offline.
#
# Why hackrf_transfer -r instead of a live GNU Radio soapy.source: this does
# single-shot, fixed-duration captures on the SAME HackRF an attack script
# used for TX moments earlier -- a CLI subprocess with a hard sample count
# (-n) is simpler to bound in time than a live source's start/stop timing.
#
# Decode reuses gr-lora_sdr's lora_sdr_lora_rx block -- the same one
# pwnsat_lora_rx.py uses -- fed from the file instead of a live SDR, with the
# same freq_xlating_fir_filter channelization down to the 250 kHz the demod
# expects.
#
# Frame boundaries: lora_sdr_lora_rx publishes one ZMQ message per decoded
# frame through a zeromq.pub_sink (a raw vector_sink_b would concatenate
# frames with no way to split them). This opens a local-loopback ZMQ PUB/SUB
# pair (127.0.0.1, free port) purely to reuse that mechanism offline.

import os
import shutil
import socket as _socket
import subprocess
import tempfile
import time
from pathlib import Path

import numpy as np
import zmq
from gnuradio import blocks
from gnuradio import filter as gr_filter
from gnuradio import gr
from gnuradio import zeromq
from gnuradio.fft import window
from gnuradio.filter import firdes
import gnuradio.lora_sdr as lora_sdr

HACKRF_CAPTURE_SAMP_RATE = 2_000_000

# HackRF -r capture and hackrf_transfer's own startup/teardown should
# finish comfortably within duration_s + this margin -- safety net for
# the subprocess timeout, not a tuned value.
CAPTURE_TIMEOUT_MARGIN_S = 5

# Fixed processing budget for the offline decode flowgraph: non-realtime
# file_source processing of a few seconds of captured audio finishes in
# well under a second of actual CPU time, so this is generous margin, not
# a tuned value -- same reasoning as pwnsat_lora_tx.py's settle_s.
DECODE_PROCESSING_BUDGET_S = 2.0


def _free_local_port() -> int:
    s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _hackrf_capture_raw(frequency: int, duration_s: float, samp_rate: int,
                        rf_gain: int, verbose: bool) -> Path:
    hackrf_transfer = shutil.which("hackrf_transfer")
    if hackrf_transfer is None:
        raise RuntimeError(
            "hackrf_transfer not found on PATH -- install HackRF tools "
            "(`brew install hackrf`), see PWNSAT-C3's INSTALL.md (github.com/Pwnsat/PWNSAT-C3)"
        )
    num_samples = int(duration_s * samp_rate)
    fd, raw_name = tempfile.mkstemp(prefix="pwnsat_rx_", suffix=".raw")
    os.close(fd)
    raw_path = Path(raw_name)

    cmd = [
        hackrf_transfer, "-r", str(raw_path),
        "-f", str(frequency), "-s", str(samp_rate),
        "-n", str(num_samples), "-l", str(rf_gain), "-g", str(rf_gain),
    ]
    if verbose:
        print(f"[RF] {' '.join(cmd)}")
        subprocess.run(cmd, text=True, timeout=duration_s + CAPTURE_TIMEOUT_MARGIN_S)
    else:
        subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=duration_s + CAPTURE_TIMEOUT_MARGIN_S,
        )
    return raw_path


def _raw_to_complex64(raw_path: Path) -> Path:
    """HackRF's -r output is signed 8-bit interleaved I/Q -- convert to
    gr_complex (float32) for GNU Radio's file_source."""
    raw = np.fromfile(raw_path, dtype=np.int8)
    iq = raw.astype(np.float32) / 128.0
    complex_sig = (iq[0::2] + 1j * iq[1::2]).astype(np.complex64)
    cf32_path = raw_path.with_suffix(".cf32")
    complex_sig.tofile(cf32_path)
    return cf32_path


def _decode_capture(cf32_path: Path, *, bandwidth: int, spreading_factor: int,
                    coding_rate: int, has_crc: bool, impl_head: bool,
                    sync_word: list, source_samp_rate: int) -> list:
    """Runs the captured file through gr-lora_sdr's own RX chain and
    returns a list of raw decoded byte-strings, one per frame found."""
    samp_rate = bandwidth  # the LoRa demod's own rate, same convention as pwnsat_lora_rx.py
    decim = source_samp_rate // samp_rate
    bandpass = firdes.complex_band_pass(
        1.0, source_samp_rate, -bandwidth / 2, bandwidth / 2, bandwidth / 50,
        window.WIN_HAMMING, 6.76,
    )

    zmq_addr = f"tcp://127.0.0.1:{_free_local_port()}"

    tb = gr.top_block("PwnsatLoraRXCapture", catch_exceptions=True)
    src = blocks.file_source(gr.sizeof_gr_complex, str(cf32_path), False)
    xlate = gr_filter.freq_xlating_fir_filter_ccc(decim, bandpass, 0, source_samp_rate)
    rx = lora_sdr.lora_sdr_lora_rx(
        bw=bandwidth, cr=coding_rate, has_crc=has_crc, impl_head=impl_head,
        pay_len=255, samp_rate=samp_rate, sf=spreading_factor,
        sync_word=sync_word, soft_decoding=True, ldro_mode=2,
        print_rx=[False, False],
    )
    zmq_sink = zeromq.pub_sink(gr.sizeof_char, 1, zmq_addr, 100, False, 1000, "", True, True)

    tb.connect(src, xlate)
    tb.connect(xlate, rx)
    tb.connect(rx, zmq_sink)

    # Subscribe BEFORE starting the flowgraph, and give the ZMQ PUB/SUB
    # handshake time to settle before any publishing happens -- otherwise
    # this is the classic "slow joiner" problem: a file-fed (non-realtime)
    # flowgraph can process and publish everything before a late SUB
    # finishes connecting, silently dropping every frame.
    ctx = zmq.Context()
    sock = ctx.socket(zmq.SUB)
    sock.connect(zmq_addr)
    sock.setsockopt(zmq.SUBSCRIBE, b"")
    time.sleep(0.5)

    tb.start()
    time.sleep(DECODE_PROCESSING_BUDGET_S)
    tb.stop()
    tb.wait()

    frames = []
    sock.setsockopt(zmq.RCVTIMEO, 300)
    while True:
        try:
            frames.append(sock.recv())
        except zmq.Again:
            break
    sock.close(0)
    ctx.term()
    return frames


def listen_for_response(frequency: int, duration_s: float = 1.5,
                        rf_gain: int = 30, bandwidth: int = 250_000,
                        spreading_factor: int = 7, coding_rate: int = 1,
                        has_crc: bool = True, impl_header: bool = False,
                        sync_word=None, verbose: bool = True) -> list:
    """Captures `duration_s` seconds of RF at `frequency` via HackRF and
    returns every raw SPP packet gr-lora_sdr managed to decode in that
    window -- usually 0 or 1 for a single command/response exchange, but
    a list in case something else also transmitted in the same window
    (e.g. the FlatSat's own periodic beacon).

    Defaults (bandwidth/sf/cr/has_crc/impl_header/sync_word) match the
    FlatSat's downlink radio (rdownlink.cpp's radio1, which never
    overrides RadioLib's CRC-on/explicit-header defaults -- confirmed by
    reading that file directly, not assumed) -- the same parameters
    pwnsat_lora_rx.py already uses successfully for live downlink RX.
    """
    if sync_word is None:
        sync_word = [0x12]
    raw_path = _hackrf_capture_raw(
        frequency, duration_s, HACKRF_CAPTURE_SAMP_RATE, rf_gain, verbose,
    )
    try:
        cf32_path = _raw_to_complex64(raw_path)
        try:
            return _decode_capture(
                cf32_path, bandwidth=bandwidth, spreading_factor=spreading_factor,
                coding_rate=coding_rate, has_crc=has_crc, impl_head=impl_header,
                sync_word=sync_word, source_samp_rate=HACKRF_CAPTURE_SAMP_RATE,
            )
        finally:
            cf32_path.unlink(missing_ok=True)
    finally:
        raw_path.unlink(missing_ok=True)
