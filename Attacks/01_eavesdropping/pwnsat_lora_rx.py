#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: PwnsatLoraRX
# Author: r0r0x
# Description: SDR-agnostic LoRa downlink receiver (RTL-SDR or HackRF via GNU Radio's native Soapy blocks)
# GNU Radio version: 3.10.12.0
#
# Uses GNU Radio's in-tree `gnuradio.soapy` module (backed by SoapySDR) as the
# radio source instead of gr-osmosdr. gr-osmosdr is a separate out-of-tree
# module that would need to be built from source on top of everything else;
# GNU Radio 3.10 already ships Soapy support, and SoapySDR + soapyrtlsdr are
# installable straight from Homebrew, so this avoids one extra from-source
# build entirely. Everything downstream (the band-pass filter, the
# gr-lora_sdr demodulator, the ZMQ publish sink) is unchanged and
# SDR-agnostic already.
#
# Device selection:
#   RTL-SDR (recommended dedicated receiver): device_args = "rtlsdr"
#   HackRF (if used for RX instead of TX):     device_args = "hackrf"
#
# Sample rate note: RTL-SDR can sample as slowly as the LoRa channel itself
# (250 kHz), so historically this flowgraph ran the source and the LoRa
# demodulator at the same rate (decim=1). HackRF's ADC has a hard minimum of
# 1 MSps -- it physically cannot sample at 250 kHz. To support both, the
# source now runs at its own `source_samp_rate` (defaults to 2 MSps for
# HackRF, or the channel bandwidth itself for anything else, e.g. RTL-SDR --
# identical behavior to before for RTL-SDR), and the frequency-translating
# FIR filter channelizes AND decimates down to the 250 kHz the LoRa
# demodulator expects, in one step.

from gnuradio import filter
from gnuradio.filter import firdes
from gnuradio import gr
from gnuradio.fft import window
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
from gnuradio import zeromq
import gnuradio.lora_sdr as lora_sdr
from gnuradio import soapy
import threading


DEFAULT_HACKRF_SOURCE_SAMP_RATE = 2000000


class PwnsatLoraRX(gr.top_block):

    # NOTE ON device_args: this selects which physical device Soapy opens
    # ("rtlsdr", "hackrf", ...) and is only read once, at `soapy.source()`
    # construction time -- it cannot be changed on an already-running
    # flowgraph the way frequency/bandwidth/gain can. That is why
    # `device_args` (and the other values that matter at construction time)
    # are accepted here as constructor arguments instead of only being
    # exposed as post-construction setters: a `set_device_args()` call after
    # `__init__` would silently do nothing to the already-opened hardware.
    # `pwnsat_rx_bridge.py` always passes these in through the constructor.
    def __init__(self, device_args="rtlsdr", frequency=916000000, bandwidth=250000,
                 zmq_address="tcp://0.0.0.0:5005", spread_factor=7,
                 rf_gain=30, if_gain=20, bb_gain=20, source_samp_rate=None):
        gr.top_block.__init__(self, "PwnsatLoraRX", catch_exceptions=True)
        self.flowgraph_started = threading.Event()

        ##################################################
        # Variables
        ##################################################
        self.bandwidth = bandwidth = bandwidth
        # samp_rate is the LoRa channel's own rate, fed to the demodulator --
        # this is NOT necessarily the same as what the hardware samples at
        # (see source_samp_rate below).
        self.samp_rate = samp_rate = bandwidth
        self.zmq_address = zmq_address = zmq_address
        self.spread_factor = spread_factor = spread_factor
        # "rtlsdr" for the first RTL-SDR found, "hackrf" for the first HackRF.
        self.device_args = device_args = device_args
        self.impl_header = impl_header = False
        self.has_crc = has_crc = False
        self.frequency = frequency = frequency
        self.coding_rate = coding_rate = 1
        # Overall/IF/baseband gain -- generic defaults Soapy maps onto
        # whatever gain stages the selected device actually exposes (RTL-SDR
        # has one tuner gain; HackRF splits this into LNA/VGA/AMP stages --
        # if_gain maps to HackRF's LNA, bb_gain to its VGA, see set_if_gain/
        # set_bb_gain below).
        self.rf_gain = rf_gain = rf_gain
        self.if_gain = if_gain = if_gain
        self.bb_gain = bb_gain = bb_gain

        if source_samp_rate is None:
            source_samp_rate = (
                DEFAULT_HACKRF_SOURCE_SAMP_RATE if "hackrf" in device_args else bandwidth
            )
        self.source_samp_rate = source_samp_rate = source_samp_rate
        # Must be an integer decimation for freq_xlating_fir_filter_ccc; a
        # non-integer ratio here means source_samp_rate was chosen poorly
        # relative to bandwidth (both are under our control via config, so
        # this should never happen in practice, but fail loudly if it does
        # rather than silently mis-channelizing).
        if source_samp_rate % samp_rate != 0:
            raise ValueError(
                f"source_samp_rate ({source_samp_rate}) must be an integer "
                f"multiple of bandwidth ({samp_rate}) for clean decimation"
            )
        self.decim = decim = int(source_samp_rate // samp_rate)

        self.bandpass = bandpass = firdes.complex_band_pass(
            1.0, source_samp_rate, -bandwidth / 2, bandwidth / 2, bandwidth / 50,
            window.WIN_HAMMING, 6.76,
        )

        ##################################################
        # Blocks
        ##################################################

        self.zeromq_pub_sink_0 = zeromq.pub_sink(gr.sizeof_char, 1, zmq_address, 100, False, 1000, '', True, True)
        self.lora_rx_0 = lora_sdr.lora_sdr_lora_rx( bw=bandwidth, cr=1, has_crc=True, impl_head=False, pay_len=255, samp_rate=samp_rate, sf=spread_factor, sync_word=[0x12], soft_decoding=True, ldro_mode=2, print_rx=[True,True])

        # "driver=<name>" is SoapySDR's canonical device-args key-value
        # syntax (matches what GNU Radio Companion itself generates for its
        # native soapy_custom_source block) -- more robust across backends
        # than relying on a bare driver name being accepted as shorthand.
        self.soapy_source_0 = soapy.source("driver=" + device_args, "fc32", 1, "", "", [""], [""])
        self.soapy_source_0.set_sample_rate(0, source_samp_rate)
        self.soapy_source_0.set_frequency(0, frequency)
        self.soapy_source_0.set_gain_mode(0, False)
        self.soapy_source_0.set_gain(0, rf_gain)
        # Analog baseband filter bandwidth: many SDRs (HackRF included, whose
        # filter only has fixed steps from 1.75 MHz up) can't be set anywhere
        # near a 250 kHz LoRa channel directly -- the real channel selection
        # happens digitally via the freq_xlating_fir_filter below regardless,
        # so this is best-effort only and never fatal if rejected/clamped.
        self._try_soapy_call(lambda: self.soapy_source_0.set_bandwidth(0, bandwidth))
        # These are optional/device-dependent capabilities in SoapySDR --
        # not every driver exposes them (e.g. SoapyRTLSDR has no automatic
        # IQ-imbalance correction), so failures here are non-fatal.
        self._try_soapy_call(lambda: self.soapy_source_0.set_frequency_correction(0, 0))
        self._try_soapy_call(lambda: self.soapy_source_0.set_dc_offset_mode(0, False))
        self._try_soapy_call(lambda: self.soapy_source_0.set_iq_balance_mode(0, False))
        self._apply_if_gain(if_gain)
        self._apply_bb_gain(bb_gain)

        self.freq_xlating_fir_filter_xxx_0 = filter.freq_xlating_fir_filter_ccc(decim, bandpass, 0, source_samp_rate)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.freq_xlating_fir_filter_xxx_0, 0), (self.lora_rx_0, 0))
        self.connect((self.soapy_source_0, 0), (self.freq_xlating_fir_filter_xxx_0, 0))
        self.connect((self.lora_rx_0, 0), (self.zeromq_pub_sink_0, 0))


    @staticmethod
    def _try_soapy_call(fn):
        # Soapy/driver-specific capability checks raise either, depending on
        # the underlying device/driver -- e.g. SoapyRTLSDR raises ValueError
        # for "not supported by this channel", other drivers raise
        # RuntimeError. Both mean "this device doesn't have this knob."
        # Returns True on success, False if the device rejected the call.
        try:
            fn()
            return True
        except (RuntimeError, ValueError):
            return False

    def _apply_if_gain(self, if_gain):
        # "IF" is the generic Soapy name a few drivers use; HackRF instead
        # names its RF front-end gain stage "LNA". Try both, first match wins.
        for name in ("IF", "LNA"):
            if self._try_soapy_call(lambda n=name: self.soapy_source_0.set_gain(0, n, if_gain)):
                return

    def _apply_bb_gain(self, bb_gain):
        # "BB" is the generic Soapy name; HackRF names its baseband variable
        # gain stage "VGA". Try both, first match wins.
        for name in ("BB", "VGA"):
            if self._try_soapy_call(lambda n=name: self.soapy_source_0.set_gain(0, n, bb_gain)):
                return

    def get_bandwidth(self):
        return self.bandwidth

    def set_bandwidth(self, bandwidth):
        self.bandwidth = bandwidth
        self.set_bandpass(firdes.complex_band_pass(
            1.0, self.source_samp_rate, -self.bandwidth / 2, self.bandwidth / 2,
            self.bandwidth / 50, window.WIN_HAMMING, 6.76,
        ))
        self._try_soapy_call(lambda: self.soapy_source_0.set_bandwidth(0, self.bandwidth))

    def get_samp_rate(self):
        return self.samp_rate

    def get_source_samp_rate(self):
        return self.source_samp_rate

    def get_zmq_address(self):
        return self.zmq_address

    def set_zmq_address(self, zmq_address):
        self.zmq_address = zmq_address

    def get_spread_factor(self):
        return self.spread_factor

    def set_spread_factor(self, spread_factor):
        self.spread_factor = spread_factor

    def get_device_args(self):
        return self.device_args

    def set_device_args(self, device_args):
        # Intentionally does NOT reopen self.soapy_source_0 -- see the note
        # on the constructor. This only updates the stored/reported value;
        # pass device_args to the constructor to actually select hardware.
        self.device_args = device_args

    def get_impl_header(self):
        return self.impl_header

    def set_impl_header(self, impl_header):
        self.impl_header = impl_header

    def get_has_crc(self):
        return self.has_crc

    def set_has_crc(self, has_crc):
        self.has_crc = has_crc

    def get_frequency(self):
        return self.frequency

    def set_frequency(self, frequency):
        self.frequency = frequency
        self.soapy_source_0.set_frequency(0, self.frequency)

    def get_coding_rate(self):
        return self.coding_rate

    def set_coding_rate(self, coding_rate):
        self.coding_rate = coding_rate

    def get_rf_gain(self):
        return self.rf_gain

    def set_rf_gain(self, rf_gain):
        self.rf_gain = rf_gain
        self.soapy_source_0.set_gain(0, self.rf_gain)

    def get_if_gain(self):
        return self.if_gain

    def set_if_gain(self, if_gain):
        self.if_gain = if_gain
        self._apply_if_gain(if_gain)

    def get_bb_gain(self):
        return self.bb_gain

    def set_bb_gain(self, bb_gain):
        self.bb_gain = bb_gain
        self._apply_bb_gain(bb_gain)

    def get_bandpass(self):
        return self.bandpass

    def set_bandpass(self, bandpass):
        self.bandpass = bandpass
        self.freq_xlating_fir_filter_xxx_0.set_taps(self.bandpass)




def main(top_block_cls=PwnsatLoraRX, options=None):
    tb = top_block_cls()

    def sig_handler(sig=None, frame=None):
        tb.stop()
        tb.wait()

        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    tb.start()
    tb.flowgraph_started.set()

    try:
        input('Press Enter to quit: ')
    except EOFError:
        pass
    tb.stop()
    tb.wait()


if __name__ == '__main__':
    main()
