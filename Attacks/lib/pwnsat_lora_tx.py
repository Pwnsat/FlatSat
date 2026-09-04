#!/usr/bin/env python3
# Not meant to be run directly -- it's a library imported by attacks/*.py,
# which call require_gnuradio.check() before importing this, so a
# wrong-Python run fails there with a clear message instead of here.
# -*- coding: utf-8 -*-
#
# SPDX-License-Identifier: GPL-3.0
#
# pwnsat_lora_tx.py
#
# HackRF LoRa transmitter for the attack scripts in this repo. Mirror
# image of PWNSAT-C3's live RX flowgraph (same gnuradio.lora_sdr LoRa
# encoding blocks), but NOT a live GNU Radio flowgraph streaming to the
# radio the way the RX side is -- read on for why.
#
# NOTE: this must run under a Python that has `gnuradio` and
# `gnuradio.lora_sdr` importable -- typically a Homebrew/system Python
# with GNU Radio installed, NOT PWNSAT-C3 backend's own .venv. Attack
# scripts call require_gnuradio.check() before importing this module, so
# running under the wrong Python fails there with a clear message
# instead of here.
#
# Radio parameters below (BW 250 kHz, SF7, CR 4/5, sync word 0x12,
# explicit header, PHY CRC disabled) are copied from
# New-firmware/ruplink.cpp's uplinkRadioConfigure(). Get any wrong and the
# SX1262 never sees the packet. The center frequency is region-dependent
# and comes from lib/regions.py.
#
# Why this renders to a file and shells out to hackrf_transfer instead of
# streaming live through a GNU Radio soapy.sink: the live soapy.sink -> HackRF
# path does not reliably reproduce a correct LoRa chirp on air. The same
# block chain captured to a FILE produces textbook-correct LoRa baseband, and
# hackrf_transfer replaying that file reproduces a clean chirp on air.
# Conclusion: gr-lora_sdr's encoding is correct; something in GNU Radio's
# live SoapySDR-sink streaming corrupts it. So this module keeps all LoRa
# correctness in gr-lora_sdr and only changes how it reaches the antenna.

import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import numpy as np
from gnuradio import gr
from gnuradio import blocks
import gnuradio.lora_sdr as lora_sdr

# New-firmware/ruplink.h + ruplink.cpp's uplinkRadioConfigure(): this is the
# uplink the FlatSat's radio0 actually listens on for telecommands. The
# separate downlink/telemetry frequency (see rdownlink.h) is not used for
# TX by any attack in this folder except where a script explicitly
# overrides it, e.g. broadcast-relay-style attacks that abuse
# BROADCAST_MSG's attacker-controlled frequency field.
#
# The exact center frequency depends on the firmware's ISM region build
# -- lib/regions.py reads $FLATSAT_REGION and picks the same defaults
# Firmware/regions.h uses (us915 default: 918 MHz uplink / 916 MHz
# downlink; eu868, eu433, as923 alternatives).
from regions import UPLINK_FREQ_HZ  # noqa: F401  (re-exported)

UPLINK_BW_HZ = 250_000
UPLINK_SF = 7
UPLINK_CR = 1  # gr-lora_sdr's cr=1 means "4/5" -- matches RadioLib's setCodingRate(5)
UPLINK_SYNC_WORD = [0x12]  # RADIOLIB_SX126X_SYNC_WORD_PRIVATE
UPLINK_IMPL_HEADER = False  # ruplink.cpp calls radio0.explicitHeader()
UPLINK_HAS_CRC = False  # ruplink.cpp calls radio0.setCRC(0)

# HackRF's ADC/DAC cannot run at the LoRa channel rate (250 kHz) directly,
# same constraint documented in pwnsat_lora_rx.py for RX. gr-lora_sdr's
# modulate block takes samp_rate and bw as independent parameters and
# generates the chirp waveform already oversampled by samp_rate/bw, so the
# rendered file is already at the rate hackrf_transfer needs -- no separate
# interpolation step.
DEFAULT_HACKRF_TX_SAMP_RATE = 2_000_000

# hackrf_transfer's -t file is raw signed-8-bit interleaved I/Q. gr-lora_sdr
# chirps are constant-envelope with magnitude ~1.0 -- scale by 100 rather
# than the full int8 range (127) to leave headroom: scaling to the full
# range makes a nearby receiver clip (magnitude readings >1.0, distorted
# chirp shape), while 100 stays comfortably above the noise floor.
HACKRF_IQ_SCALE = 100

# hackrf_transfer finishes almost instantly for these packet sizes
# (tens of ms for a ~50k-sample frame) -- this is just a safety net
# against a genuine hang, not a tuned value.
HACKRF_TRANSFER_TIMEOUT_S = 15


def _render_baseband(raw_spp: bytes, *, bandwidth: int, spreading_factor: int,
                     coding_rate: int, sync_word: list, has_crc: bool,
                     impl_header: bool, samp_rate: int, settle_s: float) -> Path:
    """Runs the LoRa TX block chain into a file_sink and returns the path
    to the resulting raw complex64 (gr_complex) baseband IQ file.

    Feeds whitening over its STREAM input (is_hex=True), not its message
    port. The message port corrupts any byte >=0x7F: whitening's message
    handler calls pmt_symbol_to_string() internally and something
    downstream re-encodes the result as UTF-8, silently turning one
    high-value byte into two bytes (e.g. real byte 0xF7 arriving as the
    two bytes C3 B7). A raw PDU (dict, u8vector) isn't a fix either --
    whitening's message port rejects it outright ("wrong_type" from
    pmt_symbol_to_string, it unconditionally expects a plain symbol).
    Hex digits over the stream port are pure 7-bit ASCII, so there is no
    string/encoding step in this path at all: nothing to mangle.

    The block chain itself (header -> add_crc -> hamming_enc ->
    interleaver -> gray_demap -> modulate) is unchanged: captured
    straight from this chain, the preamble is 8 identical, cleanly swept
    up-chirps exactly where the LoRa spec says they should be, at both
    1x and 8x oversampling.
    """
    frame_zero_padd = int(20 * (2 ** spreading_factor) * samp_rate / bandwidth)

    tb = gr.top_block("PwnsatLoraTXRender", catch_exceptions=True)
    vector_source = blocks.vector_source_b(
        list(raw_spp.hex().encode("ascii") + b","), False,
    )
    whitening = lora_sdr.whitening(True, False, ",", "packet_len")
    header = lora_sdr.header(impl_header, has_crc, coding_rate)
    add_crc = lora_sdr.add_crc(has_crc)
    hamming_enc = lora_sdr.hamming_enc(coding_rate, spreading_factor)
    interleaver = lora_sdr.interleaver(coding_rate, spreading_factor, 2, bandwidth)
    gray_demap = lora_sdr.gray_demap(spreading_factor)
    modulate = lora_sdr.modulate(
        spreading_factor, samp_rate, bandwidth, sync_word, frame_zero_padd, 8,
    )

    fd, out_name = tempfile.mkstemp(prefix="pwnsat_tx_", suffix=".cf32")
    os.close(fd)
    out_path = Path(out_name)
    sink = blocks.file_sink(gr.sizeof_gr_complex, str(out_path), False)

    tb.connect(vector_source, whitening)
    tb.connect(whitening, header)
    tb.connect(header, add_crc)
    tb.connect(add_crc, hamming_enc)
    tb.connect(hamming_enc, interleaver)
    tb.connect(interleaver, gray_demap)
    tb.connect(gray_demap, modulate)
    tb.connect(modulate, sink)

    tb.start()
    time.sleep(settle_s)
    tb.stop()
    tb.wait()

    return out_path


def _convert_to_hackrf_iq(cf32_path: Path) -> Path:
    """gr_complex (float32 I/Q pairs) -> HackRF's native signed-8-bit
    interleaved I/Q. See HACKRF_IQ_SCALE's comment for the scale factor."""
    sig = np.fromfile(cf32_path, dtype=np.complex64)
    i = np.clip(sig.real * HACKRF_IQ_SCALE, -127, 127).astype(np.int8)
    q = np.clip(sig.imag * HACKRF_IQ_SCALE, -127, 127).astype(np.int8)
    out = np.empty(len(sig) * 2, dtype=np.int8)
    out[0::2] = i
    out[1::2] = q

    hackrf_path = cf32_path.with_suffix(".hackrf.iq")
    out.tofile(hackrf_path)
    return hackrf_path


def _hackrf_transfer(iq_path: Path, frequency: int, samp_rate: int,
                     tx_gain: int, amp: bool, verbose: bool = True) -> None:
    """Shells out to hackrf_transfer for the actual on-air transmission.

    verbose=True (the default) prints the exact command and lets
    hackrf_transfer's own stdout/stderr through live -- that output is
    the HackRF driver itself confirming real RF activity (frequency
    tuned, amp enabled, measured TX power, elapsed time), independent of
    anything this script prints on its own. This project's whole point is
    demonstrating that these are real over-the-air attacks, not just
    local API calls dressed up to look like one -- verbose=False (a
    script's --quiet flag) only makes sense for automated/scripted runs
    that don't need a human watching.
    """
    hackrf_transfer = shutil.which("hackrf_transfer")
    if hackrf_transfer is None:
        raise RuntimeError(
            "hackrf_transfer not found on PATH -- install HackRF tools "
            "(`brew install hackrf`), see PWNSAT-C3's INSTALL.md (github.com/Pwnsat/PWNSAT-C3)"
        )
    cmd = [
        hackrf_transfer, "-t", str(iq_path),
        "-f", str(frequency), "-s", str(samp_rate),
        "-x", str(tx_gain), "-a", "1" if amp else "0",
    ]
    if verbose:
        print(f"[RF] {' '.join(cmd)}")
        result = subprocess.run(cmd, text=True, timeout=HACKRF_TRANSFER_TIMEOUT_S)
        stderr_for_error = "(see hackrf_transfer output above)"
    else:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=HACKRF_TRANSFER_TIMEOUT_S,
        )
        stderr_for_error = result.stderr
    if result.returncode != 0:
        raise RuntimeError(
            f"hackrf_transfer failed (exit {result.returncode}):\n{stderr_for_error}"
        )


class PwnsatLoraTX:
    """One-shot LoRa transmitter: construct, call transmit(). Renders the
    packet to baseband IQ via gr-lora_sdr's own block chain, then hands
    that file to hackrf_transfer for the actual on-air transmission --
    see the module docstring for why this isn't a live GNU Radio
    flowgraph streaming to the radio.

    Unlike PwnsatLoraRX (long-running, continuously receiving), this is
    used fresh for each packet an attack script wants to send -- every
    attack in this folder only ever transmits one or a handful of
    packets, not a stream.
    """

    def __init__(self, device_args: str = "hackrf", frequency: int = UPLINK_FREQ_HZ,
                bandwidth: int = UPLINK_BW_HZ, spreading_factor: int = UPLINK_SF,
                coding_rate: int = UPLINK_CR, sync_word=None,
                has_crc: bool = UPLINK_HAS_CRC, impl_header: bool = UPLINK_IMPL_HEADER,
                tx_gain: int = 47, source_samp_rate=None):
        if device_args != "hackrf":
            raise ValueError(
                f"device_args={device_args!r} not supported -- this module shells "
                "out to hackrf_transfer, which only drives a HackRF. Every attack "
                "here uses the HackRF by design (RTL-SDR stays dedicated "
                "to PWNSAT-C3)."
            )
        self.device_args = device_args
        self.frequency = frequency
        self.bandwidth = bandwidth
        self.spreading_factor = spreading_factor
        self.coding_rate = coding_rate
        self.sync_word = list(sync_word) if sync_word is not None else list(UPLINK_SYNC_WORD)
        self.has_crc = has_crc
        self.impl_header = impl_header
        self.tx_gain = tx_gain
        self.source_samp_rate = source_samp_rate or DEFAULT_HACKRF_TX_SAMP_RATE
        if self.source_samp_rate % self.bandwidth != 0:
            raise ValueError(
                f"source_samp_rate ({self.source_samp_rate}) must be an integer "
                f"multiple of bandwidth ({self.bandwidth}) for a clean oversample ratio"
            )

    def transmit(self, raw_spp: bytes, settle_s: float = 0.5, verbose: bool = True) -> None:
        """Render raw_spp (the exact SPP bytes -- primary header +
        secondary header, if any + data field, no USB framing) to LoRa
        baseband IQ, then transmit it via hackrf_transfer. Blocks until
        the transmission is complete.

        settle_s only needs to cover non-real-time flowgraph processing
        now (rendering to a file, not pacing samples to real hardware),
        so it can be much shorter than the old live-streaming version's
        default -- 0.5s is generous margin for a packet that's a handful
        of bytes.

        verbose (default True): print the exact hackrf_transfer command
        and let its own output through live, so it's visible proof this
        went out over real RF -- see _hackrf_transfer()'s docstring.
        """
        cf32_path = _render_baseband(
            raw_spp,
            bandwidth=self.bandwidth, spreading_factor=self.spreading_factor,
            coding_rate=self.coding_rate, sync_word=self.sync_word,
            has_crc=self.has_crc, impl_header=self.impl_header,
            samp_rate=self.source_samp_rate, settle_s=settle_s,
        )
        try:
            hackrf_iq_path = _convert_to_hackrf_iq(cf32_path)
            try:
                _hackrf_transfer(
                    hackrf_iq_path, self.frequency, self.source_samp_rate,
                    self.tx_gain, amp=True, verbose=verbose,
                )
            finally:
                hackrf_iq_path.unlink(missing_ok=True)
        finally:
            cf32_path.unlink(missing_ok=True)


def transmit_packet(raw_spp: bytes, frequency: int = UPLINK_FREQ_HZ,
                    device_args: str = "hackrf", tx_gain: int = 47,
                    settle_s: float = 0.5, verbose: bool = True) -> None:
    """Convenience one-shot: build a fresh transmitter, send one packet.
    What every attacks/*.py script should call -- see
    attacks/07_resetc.py for the minimal usage pattern.

    verbose (default True): show hackrf_transfer's own output live, so
    there's visible proof this is a real RF transmission and not just a
    local function call -- pass verbose=False (wire up a script's
    --quiet flag) for unattended/scripted runs. See
    PwnsatLoraTX.transmit()'s docstring."""
    tb = PwnsatLoraTX(device_args=device_args, frequency=frequency, tx_gain=tx_gain)
    tb.transmit(raw_spp, settle_s=settle_s, verbose=verbose)
