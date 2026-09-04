# FlatSat Attacks 00–07

Eight attack scripts exploiting the vulnerabilities documented in
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
| `regions.py` | ISM region presets (mirrors `../../Firmware/regions.h`) — reads `$FLATSAT_REGION` and exposes `UPLINK_FREQ_HZ`/`DOWNLINK_FREQ_HZ` (plus `_MHZ` variants) so TX/RX default to whatever the firmware was built for. See [Region configuration](#region-configuration). |
| `pwnsat_packets.py` | Bootstraps `pwnsat_tools/` onto `sys.path` and re-exports packet building/decoding. |
| `flatsat_usb.py` | `FlatSatUSB` — the USB serial transport the `*_usb.py` scripts use. |
| `pwnsat_lora_tx.py` | HackRF TX helper (shells out to `hackrf_transfer`). |
| `pwnsat_lora_rx_capture.py` | GNU Radio LoRa RX capture helper. |
| `pwnsat_catsniffer_rx.py` | CatSniffer-based dedicated downlink listener (two-radio setup). |
| `pwnsat_rtlsdr_rx.py` | RTL-SDR downlink listener, reuses `01_eavesdropping/pwnsat_lora_rx.py`. |
| `decrypt_display.py` | Decrypts and pretty-prints a captured downlink payload. |
| `require_gnuradio.py` | Fails fast with a clear message if GNU Radio isn't importable. |

## Region configuration

The `_rf.py` scripts default their TX (uplink) and RX (downlink) center
frequencies to whatever ISM region the FlatSat firmware was built for.
Pick one via the `FLATSAT_REGION` env var — the same four presets as
[Firmware/regions.h](../Firmware/README.md#region-configuration):

| `FLATSAT_REGION` | Uplink (TX) | Downlink (RX) |
|---|---|---|
| `us915` (default) | 918.0 MHz | 916.0 MHz |
| `eu868` | 869.0 MHz | 867.0 MHz |
| `eu433` | 434.5 MHz | 433.5 MHz |
| `as923` | 924.0 MHz | 922.0 MHz |

```shell
# match a firmware built for EU868 (`pio run -e pico_tinyusb_eu868`):
FLATSAT_REGION=eu868 python 07_resetc/07_resetc_rf.py
```

Each `_rf.py` script also accepts a `--frequency` flag to override just
that one run without changing the env. `lib/regions.py` holds the table
and must stay in sync with `../Firmware/regions.h`.

## Safety

Every script here transmits over RF or sends real commands. Only run these
against a FlatSat board, lab transmitter, or signal source you own or are
explicitly authorized to test.
