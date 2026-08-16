# Tau LiDAR Camera payload

A new FlatSat **payload subsystem**: an [Onion Tau LiDAR Camera](https://github.com/OnionIoT/tau-lidar-camera)
(ESPROS epc660 Time-of-Flight, 160×60, 0.1–4.5 m, millimetres) exposed to the
spacecraft as CCSDS telemetry, plus the host-side bridge that drives it and a
hardware-free test/simulation path.

## Why a host bridge (and not a firmware sensor)

The Tau is a **USB-C depth camera** — it enumerates as a USB-CDC device and
must be driven by something with USB-*host* capability. FlatSat's OBC is an
RP2040 whose single native USB is already a CDC *device* (the telecommand
link), so the camera cannot hang directly off the flight computer.

That constraint is realistic: real spacecraft cameras are *smart payloads* with
their own processor; the OBC commands, ingests, and downlinks them. This module
follows that architecture, which FlatSat already models with its
store-and-forward payload path (`payloadForwardCount`):

```
Tau camera ──USB──▶ payload host (tau_lidar_bridge.py, Tau SDK)
                        │  reduce 160×60 depth frame → {min,max,mean,center mm, valid%, amplitude}
                        │  CCSDS SPP_APID_TC_SET_LIDAR_FRAME (0x15)
                        ▼
                    RP2040 OBC (Firmware/lidar.cpp) ──LoRa / USB──▶ ground (SPP_APID_TM_LIDAR 0x14)
```

## Files

| File | What it does |
|---|---|
| `tau_lidar_payload.py` | Pure-stdlib core: reduces a depth frame to a `LidarSummary` and packs/unpacks the exact wire block the firmware reads. No numpy / pyserial / SDK, so it runs and is unit-tested with no hardware. |
| `tau_lidar_bridge.py` | Host runner. Reads the Tau over USB (SDK, lazy-imported) or synthesizes frames (`--simulate`), reduces each one, and forwards it to the OBC reusing FlatSat's own SPP builder (`Attacks/lib`), degrading to `--dry-run` if the board/toolchain is absent. |
| `tests/test_lidar_payload.py` | pytest, hardware-free: reduction, invalid-pixel masking, saturation, amplitude gating, and byte-exact wire round-trips. |

## New CCSDS APIDs (registered in `Firmware/mission.h`)

| APID | Dir | Name | Meaning |
|---|---|---|---|
| `0x15` | TC | `SET_LIDAR_FRAME` | payload host uplinks a reduced depth-frame summary |
| `0x14` | TC | `GET_LIDAR` | request the latest LiDAR status |
| `0x14` | TM | `LIDAR` | LiDAR status/report downlink |

New telemetry IDs `SC_TM_ID_LIDAR_{MIN,MAX,MEAN,CENTER,VALID_PCT,AMPLITUDE}`
(`0x0B`–`0x10`) label the reduced fields.

## Wire format

The `SET_LIDAR_FRAME` telecommand data field is `SPACECRAFT_ID` (1 byte) then a
21-byte little-endian summary block — identical layout on both sides
(`tau_lidar_payload.encode_summary()` ⇄ `Firmware/lidar.cpp lidarIngestSummary()`):

| Offset | Type | Field |
|---|---|---|
| 0 | u8 | `frame_type` (0 DIST / 1 +GRAY / 2 +AMPL) |
| 1–2 | u16 | `min_mm` |
| 3–4 | u16 | `max_mm` |
| 5–6 | u16 | `mean_mm` |
| 7–8 | u16 | `center_mm` |
| 9 | u8 | `valid_pct` (0–100) |
| 10–11 | u16 | `amplitude` |
| 12–13 | u16 | `width` (160) |
| 14–15 | u16 | `height` (60) |
| 16–19 | u32 | `frame_count` |
| 20 | u8 | `status` (bit0 valid, bit1 all-invalid, bit2 saturated) |

Distances follow the firmware LE convention (`bufferPackU16LE`). No-return /
out-of-window pixels use the sentinel `0xFFFF` — the epc660 encodes them as `0`
or a large value, not NaN, so the reducer masks by the physical window
`[100, 4500] mm` (and rejects NaN defensively).

## Running it

Hardware-free (no camera, no board) — synthesize frames and print the packets:

```bash
python3 Payloads/lidar/tau_lidar_bridge.py --simulate --dry-run --frames 5
```

With a real Tau camera on the payload host, forwarding to a connected FlatSat:

```bash
pip install TauLidarCamera            # pulls in TauLidarCommon, pyserial, numpy
python3 Payloads/lidar/tau_lidar_bridge.py --port /dev/ttyACM0 --obc-port /dev/ttyACM1
```

Query the latest status from the ground with the existing FlatSat tooling by
sending `GET_LIDAR` (APID `0x14`).

Run the tests:

```bash
python3 -m pytest Payloads/lidar/tests/ -q
```

## Intentional vulnerability

FlatSat is vulnerable-by-design, and (per `Firmware/README.md`) every subsystem
ships at least one teachable weakness. This payload's is **payload-data
spoofing**: the OBC's `SET_LIDAR_FRAME` handler (`Firmware/lidar.cpp`) trusts
the reduced summary from the payload host verbatim — no plausibility check on
the distances, no `MISSION_MODE_PAYLOAD` / `payloadArmed` gate, and no
authentication of the payload processor beyond the shared link — then
republishes it as authoritative spacecraft telemetry. An attacker who can inject
that telecommand (or a compromised payload host) can make the satellite report
fabricated LiDAR ranges. `tau_lidar_bridge.py --dry-run` prints the exact bytes,
which makes crafting a spoofed frame a one-line exercise — a clean lead-in to a
"trust the payload bus" lesson.

## Upstream note

The Tau SDK (`TauLidarCamera`, `TauLidarCommon`) is MIT-licensed but effectively
dormant (last PyPI release 0.0.5, 2021); it is stable and pinned by API here.
The camera also speaks a documented framed binary protocol (`0xF5` command /
`0xFA` data + CRC32) over its CDC link, so a future USB-host-capable variant
could drive it directly — see `TauLidarCamera/constants.py` upstream.
