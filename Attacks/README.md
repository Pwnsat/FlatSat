# FlatSat Attacks 00–08

Nine attack scripts exploiting the vulnerabilities documented in
[`../Firmware/`](../Firmware/), each available in two variants:

- **`*_rf.py`** — the physically-realistic version, over the air via
  HackRF (uplink) and RTL-SDR/CatSniffer (downlink). Confirmed on real
  hardware.
- **`*_usb.py`** — the same finding, delivered over FlatSat's USB serial
  link instead of RF. Useful to rehearse the effect without an SDR.

| Folder | Attack | APID(s) |
| --- | --- | --- |
| `00_recon_apid_enum/` | Unauthenticated black-box APID enumeration | various |
| `01_eavesdropping/` | Passive downlink decryption (static AES-128 key) | `SEND_TM` |
| `02_fuzzing_crash/` | `BROADCAST_MSG` integer underflow crash | `0x06` |
| `03_command_injection/` | Unauthenticated `SET_THRUSTER` | `0x04` |
| `04_gps_spoofing/` | Real GPS L1 spoofing + a debug GPS-override demo | — |
| `05_gs_auth_spoofing/` | Ground-station auth bypass (static XOR key) | `0x12` |
| `06_replay/` | Telecommand replay (no anti-replay) | `0x01` |
| `07_resetc/` | Unauthenticated `RESETC` reboot | `0x02` |
| `08_lidar_payload_spoof/` | Tau LiDAR payload-data spoofing → poisons collision-avoidance autonomy into an uncommanded thruster burn | `0x15` |

> **Note on `08`:** unlike `00`–`07`, the LiDAR payload-spoofing scripts have
> not yet been confirmed on real hardware — the reduction/codec and the forged
> `SET_LIDAR_FRAME` bytes are tested (see `../Payloads/lidar/`), and the wire
> layout was verified byte-for-byte against the firmware, but the on-air /
> on-board run is pending a physical bring-up. `08` exercises the new
> [Tau LiDAR payload subsystem](../Payloads/lidar/).

Full step-by-step walkthrough for each attack — prerequisites, exact
commands, and how to confirm it worked — is in the wiki:
**[Attack Walkthroughs (00–07)](https://github.com/Pwnsat/FlatSat/wiki/Attack-Walkthroughs-00-07)**.
This README only lists what's here; it isn't a substitute for that page.

## Dependency: PWNSAT-C3

None of these scripts vendor their own SPP/CCSDS codec or AES
implementation — `lib/pwnsat_packets.py` and `lib/flatsat_usb.py` import
`pwnsat_tools/` from **[PWNSAT-C3](https://github.com/Pwnsat/PWNSAT-C3)**,
the ground-station dashboard repo. Clone both repos as siblings under the
same parent directory:

```shell
git clone https://github.com/Pwnsat/FlatSat
git clone https://github.com/Pwnsat/PWNSAT-C3
```

```
some-parent-dir/
├── FlatSat/
│   └── Attacks/   <- you are here
└── PWNSAT-C3/
    └── pwnsat_tools/
```

No other install step is needed beyond what
[PWNSAT-C3's own INSTALL.md](https://github.com/Pwnsat/PWNSAT-C3/wiki/Getting-Started)
already covers (Python deps, and the optional GNU Radio/SoapySDR/HackRF
toolchain the `_rf.py` scripts need).

## `lib/`

Shared code the scripts above import, not run directly:

| File | Purpose |
| --- | --- |
| `pwnsat_packets.py` | Bootstraps `pwnsat_tools/` onto `sys.path` and re-exports packet building/decoding. |
| `flatsat_usb.py` | `FlatSatUSB` — the USB serial transport the `*_usb.py` scripts use. |
| `pwnsat_lora_tx.py` | HackRF TX helper (shells out to `hackrf_transfer`). |
| `pwnsat_lora_rx_capture.py` | GNU Radio LoRa RX capture helper. |
| `pwnsat_catsniffer_rx.py` | CatSniffer-based dedicated downlink listener (two-radio setup). |
| `pwnsat_rtlsdr_rx.py` | RTL-SDR downlink listener, reuses `01_eavesdropping/pwnsat_lora_rx.py`. |
| `decrypt_display.py` | Decrypts and pretty-prints a captured downlink payload. |
| `require_gnuradio.py` | Fails fast with a clear message if GNU Radio isn't importable. |

## Safety

Every script here transmits over RF or sends real commands. Only run these
against a FlatSat board, lab transmitter, or signal source you own or are
explicitly authorized to test.
