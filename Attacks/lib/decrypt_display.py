#!/usr/bin/env python3
# Shared display/decrypt helpers for the eavesdropping attack -- used both
# live (pwnsat_rx_bridge.py) and offline (decode_capture.py, replaying a
# saved .bin with no radio hardware). Deliberately has NO gnuradio import
# anywhere in this file or its dependencies, so decode_capture.py can analyze
# a capture without a GNU Radio Python or a HackRF.
import string
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pwnsat_packets import AES_KEY, decode_packet, decrypt_payload  # noqa: E402


def hexdump(data: bytes, width: int = 16) -> str:
  lines = []

  for offset in range(0, len(data), width):
    chunk = data[offset:offset + width]

    hex_bytes = ' '.join(f"{b:02X}" for b in chunk)
    hex_bytes = hex_bytes.ljust(width * 3)

    ascii_bytes = ''.join(chr(b) if chr(b) in string.printable and b >= 0x20 else '.' for b in chunk)

    lines.append(f"{offset:08X}  {hex_bytes}  {ascii_bytes}")

  return "\n".join(lines)


def try_decrypt_packet(raw_spp: bytes) -> str:
  """The actual eavesdropping attack, one packet at a time: split the SPP
  primary header (never encrypted -- version/type/APID/sequence/length are
  always plaintext, see spp_tools.decode_packet) from the data field, then
  decrypt that data field with the exact static AES key PWNSAT-C3 itself
  uses (pwnsat_tools/pwnsat_crypto.py's AES_KEY -- the same literal
  "PWNsatLabKey1234" that's also hardcoded in New-firmware/secure_link.cpp).
  No key exchange happened, none is needed: anyone with this repo already
  has it.

  Never raises -- eavesdropped RF is routinely partial or corrupted (a
  dropped chirp, a collision with the uplink), and this is a passive
  display helper, not something that should ever crash its caller,
  whether that's a live receive loop or an offline capture replay.
  """
  # STEP 3 -- split header from data: the 6-byte SPP primary header
  # (version/type/APID/sequence/length) is never encrypted, so APID and
  # sequence are already readable with zero decryption effort.
  try:
    packet = decode_packet(raw_spp)
  except ValueError as exc:
    return f"  [!] could not parse SPP primary header: {exc}"

  lines = [f"  [STEP 3] header parsed (cleartext) -- APID: {packet.apid_name} (0x{packet.apid:02X})  seq={packet.sequence_count}"]

  if not packet.data:
    lines.append("  (no data field -- nothing to decrypt)")
    return "\n".join(lines)

  lines.append(f"  ciphertext ({len(packet.data)} bytes): {packet.data.hex()}")

  # STEP 4 -- ECB tell (dossier "Causa raiz", eavesdropping section): AES-ECB
  # encrypts every 16-byte block independently with no IV, so identical
  # plaintext blocks -- e.g. the zero-padding every short payload gets --
  # produce identical ciphertext blocks. Visible before decrypting a byte.
  blocks = [packet.data[i:i + 16] for i in range(0, len(packet.data), 16)]
  if len(blocks) > 1 and len(set(blocks)) < len(blocks):
    lines.append("  [STEP 4] [ECB tell] repeated 16-byte ciphertext block(s) -- padding pattern visible pre-decrypt")

  # STEP 5 -- decrypt with the known static key. No key exchange ever
  # happened; this literal key ships in this same repo's source code.
  try:
    plain = decrypt_payload(packet.data, AES_KEY)
    ascii_plain = "".join(chr(b) if 32 <= b < 127 else "." for b in plain)
    lines.append(f"  [STEP 5] decrypted with the known static key ({AES_KEY!r})")
    lines.append(f"  PLAINTEXT ({len(plain)} bytes): {plain.hex()}")
    lines.append(f"  ascii:     {ascii_plain}")
  except Exception as exc:  # noqa: BLE001 -- see docstring, must never propagate
    lines.append(f"  [!] decrypt failed (secure_link off right now, or corrupted RF): {exc}")

  return "\n".join(lines)
