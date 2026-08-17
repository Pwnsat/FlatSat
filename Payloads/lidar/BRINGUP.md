# Tau LiDAR payload — zero-to-hardware bring-up

A single runbook that takes you from an empty bench to a working Tau LiDAR
payload on a FlatSat, feeding real depth telemetry, and then to running the
payload-spoofing attack and watching it poison the onboard autonomy into an
uncommanded thruster burn.

It is written to *teach*, not just to copy-paste: each phase says what you are
doing, what "working" looks like, and **why** — so by the end you understand the
whole data path, the CCSDS wire format, and the two security lessons the module
was built to demonstrate.

> **Read the [`README.md`](README.md) first** for the component reference (APIDs,
> wire layout, file map). This document is the *procedure*; the README is the
> *reference*.

---

## 0. The mental model (read this before touching anything)

The Tau LiDAR is a **USB-C depth camera** (ESPROS epc660 Time-of-Flight, 160×60
pixels, 0.1–4.5 m, millimetres). It must be driven by something with USB-*host*
capability. The FlatSat OBC is an RP2040 whose only native USB is already a CDC
*device* (its telecommand link) — so the camera **cannot** hang off the flight
computer directly.

That constraint is realistic, not a limitation: real spacecraft cameras are
*smart payloads* with their own processor; the OBC commands, ingests, and
downlinks them. This module follows that architecture. Nothing is wired between
the camera and the FlatSat — they meet **in software on a payload host**:

```
                        PAYLOAD HOST (Raspberry Pi / laptop)
                        ┌───────────────────────────────────────┐
 Tau LiDAR ──USB-C──►   │ tau_lidar_bridge.py                    │
 (depth frames)         │   1. read 160×60 depth frame (SDK)     │
                        │   2. reduce → {min,max,mean,center mm,  │
                        │      valid%, amplitude}  (21 bytes)     │
                        │   3. wrap as CCSDS SET_LIDAR_FRAME (TC  │
                        │      0x15), reuse FlatSat's SPP builder │
                        └───────────────┬───────────────────────┘
                                        │ USB serial (CCSDS/SPP)
                                        ▼
                        FlatSat OBC (RP2040)  ──── RF (LoRa) ────►  ground / PWNSAT-C3
                        ┌───────────────────────────────────────┐
                        │ lidar.cpp   store the summary          │
                        │ autonomy.cpp  react to proximity  ─────┼─► fires thruster on hazard
                        │ worker.cpp  re-emit as LIDAR TM (0x14) │
                        │             + AUTONOMY TM (0x16)       │
                        └───────────────────────────────────────┘
```

**Two deliberate vulnerabilities live along this path** (FlatSat is
vulnerable-by-design):

1. **Payload-data spoofing** — the OBC trusts the reduced summary from the
   payload host verbatim (no plausibility bound, no mission-mode gate, no
   payload-source authentication). Anyone who can put a `SET_LIDAR_FRAME` on the
   link makes the satellite report whatever ranges they choose.
2. **Sensor-fusion poisoning** — the onboard collision-avoidance autonomy reads
   the IMU *as if* fusing it, but actuates on the LiDAR proximity **alone**. A
   spoofed "collision" frame therefore fires the avoidance thruster with no
   independent sensor agreement.

Everything below builds up to demonstrating both, on real hardware.

---

## 1. Bill of materials

**Required (core functionality + USB attack):**

| Item | Notes |
|---|---|
| FlatSat board | RP2040 OBC + dual SX1262 — the spacecraft |
| Onion **Tau LiDAR Camera** | USB-C ToF camera (the payload sensor) |
| Payload host | Raspberry Pi 4/5 or any Linux/macOS laptop with **two** free USB ports |
| 2× USB cables | one USB-C to the camera, one to the FlatSat OBC |

**Optional (RF attack + realistic link):**

| Item | Notes |
|---|---|
| HackRF One | uplink TX for the `_rf.py` attack variant |
| RTL-SDR / CatSniffer | downlink RX to watch telemetry over the air |
| SMA antennas (ISM band) | 433 or 915 MHz per your region |

The **USB attack variant needs no SDR** — it delivers the same telecommand over
the OBC's serial link, so you can prove the whole chain with just the two
required USB devices before adding radios.

USB topology once assembled:

```
[Tau LiDAR] ──USB-C──┐
                     ├──► [Payload host] ──USB──► [FlatSat OBC]
[HackRF (optional)] ─┘                    (RF, optional) ⇢ [FlatSat radios]
```

---

## 2. Prerequisites (software you install once)

On the **payload host**:

- **Python 3.9+** (`python3 --version`). 3.12 is what the CI gate uses.
- **PlatformIO Core** (`pip install platformio`) *or* the Arduino IDE with the
  [earlephilhower RP2040 core](https://github.com/earlephilhower/arduino-pico) —
  to build and flash the firmware. See [`../../Firmware/README.md`](../../Firmware/README.md).
- **git**.
- *(RF only)* GNU Radio + SoapySDR + HackRF host tools (`hackrf_transfer`). See
  [PWNSAT-C3's INSTALL guide](https://github.com/Pwnsat/PWNSAT-C3/wiki/Getting-Started).

---

## 3. Get the code

The CCSDS transport and the attack scripts import `pwnsat_tools` from the
**PWNSAT-C3** repo, so clone both repos **as siblings under one parent**:

```bash
mkdir flatsat-lab && cd flatsat-lab
git clone https://github.com/Pwnsat/FlatSat
git clone https://github.com/Pwnsat/PWNSAT-C3
```

To use *this* contribution before it is merged, check the branch out in the
FlatSat clone:

```bash
cd FlatSat
git remote add lidar https://github.com/astrorekcah/FlatSat.git
git fetch lidar && git checkout astro/lidar-tau-payload
cd ..
```

Expected layout (the bridge and attacks rely on this exact sibling arrangement):

```
flatsat-lab/
├── FlatSat/
│   ├── Firmware/        <- lidar.cpp, autonomy.cpp, worker.cpp ...
│   ├── Payloads/lidar/  <- you are reading BRINGUP.md here
│   └── Attacks/         <- 08_lidar_payload_spoof/, lib/
└── PWNSAT-C3/
    └── pwnsat_tools/    <- spp_tools.py, pwnsat_crypto.py ...
```

---

## 4. Phase A — prove the pipeline with **no hardware**

Do this first. It builds confidence and teaches the data path before a single
cable is plugged in. None of it needs the camera, the board, or PWNSAT-C3.

**A1. Run the tests** (the reduction + the byte-exact wire codec):

```bash
cd FlatSat
python3 -m pytest Payloads/lidar/tests/ -q
```
Expect `15 passed`. **Why it matters:** these lock the 21-byte summary layout
that the host and the firmware both depend on — if they pass, the two languages
agree on the wire format.

**A2. Watch a frame become a telecommand:**

```bash
python3 Payloads/lidar/tau_lidar_bridge.py --simulate --dry-run --frames 3
```
You'll see a synthesized scene reduced to scalars and printed as the exact
22-byte `SET_LIDAR_FRAME` payload (1 `SPACECRAFT_ID` + 21 summary). **Why it
matters:** this is *precisely* the byte string the real bridge will send over
USB — the only thing hardware changes is the transport, not the content.

**A3. See the attack shape** (bytes only, still no board):

```bash
python3 -c "import sys; sys.path.insert(0,'Payloads/lidar'); \
from tau_lidar_payload import spoof_summary, build_lidar_payload; \
print(build_lidar_payload(spoof_summary('collision')).hex())"
```
That hex is the forged "phantom obstacle" frame `Attacks/08` transmits.

✅ **Checkpoint:** tests green, and you can read a depth frame turning into
CCSDS bytes. You now understand the payload before powering anything on.

---

## 5. Phase B — build and flash the firmware

```bash
cd FlatSat/Firmware
pio run                     # builds .pio/build/pico_tinyusb/firmware.uf2
```
Flash: hold the Pico's **BOOTSEL** button while plugging the FlatSat OBC into
USB — it mounts as a mass-storage volume — then copy the `.uf2` onto it. It
reboots into the new firmware on its own. (A pre-built image also ships at
`Firmware/build/flatsat-firmware.uf2` if you'd rather not build.)

**Confirm it booted:** open the OBC's USB serial console (e.g.
`screen /dev/ttyACM0 115200`, or PWNSAT-C3's console). On boot you should see,
among the subsystem init lines:

```
[INFO] LiDAR payload subsystem ready (host-bridge)
```

✅ **Checkpoint:** the firmware with the LiDAR + autonomy subsystems is running
on the board and announces the payload at startup.

---

## 6. Phase C — bring up the camera + bridge

**C1. Install the SDK and confirm the camera** (payload host):

```bash
cd FlatSat
python3 -m pip install -r Payloads/lidar/requirements.txt
python3 -c "from TauLidarCamera.camera import Camera; print(Camera.scan())"
```
`Camera.scan()` should list a serial port (Linux `/dev/ttyACM*`, macOS
`/dev/cu.usbmodem*`). If it's empty, replug the camera and check permissions
(Linux: add yourself to the `dialout` group).

**C2. Dry-run the real camera path** (reduce real frames, don't transmit yet):

```bash
python3 Payloads/lidar/tau_lidar_bridge.py --port <camera-port> --dry-run --frames 5
```
Wave your hand in front of the lens — `min`/`center` should drop toward a few
hundred millimetres. **Why:** this proves the camera→reduce half works and lets
you sanity-check the numbers before they hit the spacecraft.

**C3. Forward to the FlatSat for real:**

```bash
python3 Payloads/lidar/tau_lidar_bridge.py \
    --port <camera-port> --obc-port <obc-port>
```
`--port` is the **camera**; `--obc-port` is the **FlatSat OBC** (omit either to
autodetect). The bridge now reads frames, reduces them, and sends
`SET_LIDAR_FRAME` telecommands to the OBC. **Encryption note:** the OBC's secure
link is AES-on by default and the bridge matches it by default — only add
`--no-encrypt` if you disabled AES on the board, or the OBC will fail to decrypt.

✅ **Checkpoint:** live depth telemetry is flowing camera → host → OBC.

---

## 7. Phase D — verify telemetry on the ground

Every frame the OBC ingests it re-emits as a **`LIDAR` telemetry packet (APID
`0x14`)** on both the USB and RF downlinks. Confirm it the way you prefer:

- **PWNSAT-C3 dashboard** — its telemetry view will show the LIDAR packets;
  the min/mean/center track what the camera sees.
- **Over the air** — if you have an RTL-SDR/CatSniffer, the downlink listeners
  in `Attacks/lib/` (`pwnsat_rtlsdr_rx.py`, `pwnsat_catsniffer_rx.py`) capture
  and decrypt them.
- **Raw** — tools that can send an arbitrary TC (`FlatSatUSB.send_raw_tc`) can
  poll `GET_LIDAR` (`0x14`) / `GET_AUTONOMY` (`0x16`) on demand.

✅ **Checkpoint:** you can see the spacecraft reporting the real scene. The
"honest" system is fully working — everything below is the security lesson.

---

## 8. Phase E — spoof the payload (lesson 1)

Now inject a **forged** depth summary and watch the satellite believe it.

**USB (no SDR):**
```bash
cd FlatSat/Attacks/08_lidar_payload_spoof
./08_lidar_payload_spoof_usb.py --preset collision
```
The script builds a forged `SET_LIDAR_FRAME`, sends it over the OBC serial link,
then reads the reply telemetry back. Expect:

```
[+] CONFIRMED via LIDAR TM (0x14): satellite now reports min=180mm mean=350mm center=180mm
```

**RF (over the air, needs HackRF):**
```bash
./08_lidar_payload_spoof_rf.py --preset collision --gain 20
```

Presets: `collision` (phantom obstacle ~180 mm), `clear` (open path ~4.4 m),
`blind` (all no-return). Override any field with `--min-mm`, `--center-mm`, etc.

**The lesson:** the OBC never checked whether that depth data was physically
plausible or *who* supplied it. On a real spacecraft the payload processor would
sign its frames and the OBC would bound-check them; here it trusts the bus.

---

## 9. Phase F — poison the autonomy (lesson 2)

The spoof isn't just cosmetic. The onboard **collision-avoidance autonomy**
(`Firmware/autonomy.cpp`) reacts to that proximity on every ingested frame. With
the satellite in an operational mission mode (nominal/payload/science — the
default is nominal), re-run the USB spoof:

```bash
./08_lidar_payload_spoof_usb.py --preset collision
```
Now you should *also* see:

```
[!] POISONED: collision-avoidance autonomy fired the thruster (power=200)
    off the spoofed proximity -- the IMU (…mg, no real motion) was never cross-checked.
```
Confirm the actuator moved: the FlatSat serial console shows the thruster power
change, and PWNSAT-C3's thruster gauge jumps. Put the satellite in **safe mode**
(`SET_MISSION_MODE` → `SAFE`) and repeat — the hazard is still detected but the
thruster **does not** fire (autonomy is inhibited), showing the mode gate works
while the fusion check does not.

**The lesson:** the autonomy *read* the IMU but never required it to agree. One
poisoned sensor channel drove a physical maneuver. Fault-tolerant autonomy needs
multi-sensor consensus, plausibility bounds, and rate limits before actuating —
this is the sensor-fusion-poisoning failure mode, end to end.

---

## 10. Reference — the wire, the APIDs, the knobs

**New APIDs** (full registry in `Firmware/mission.h`):

| APID | Dir | Name | Meaning |
|---|---|---|---|
| `0x15` | TC | `SET_LIDAR_FRAME` | host uplinks a reduced depth summary |
| `0x14` | TC/TM | `GET_LIDAR` / `LIDAR` | request / report LiDAR status |
| `0x16` | TC/TM | `GET_AUTONOMY` / `AUTONOMY` | request / report autonomy decision |

**`SET_LIDAR_FRAME` payload** = `SPACECRAFT_ID` (1 B) + 21-byte little-endian
summary (`frame_type`, `min/max/mean/center` mm, `valid_pct`, `amplitude`,
`width`, `height`, `frame_count`, `status`). Full table in [`README.md`](README.md).

**Autonomy trip point:** `AUTONOMY_HAZARD_MM` = 500 mm, avoidance thruster power
200 — both in `Firmware/autonomy.h`.

---

## 11. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `Camera.scan()` returns `[]` | camera not enumerated — replug USB-C; Linux add user to `dialout` |
| bridge prints `OBC link unavailable … falling back to --dry-run` | PWNSAT-C3 not a sibling of FlatSat, or the OBC isn't connected — check §3 layout and `--obc-port` |
| frames send but OBC logs a decrypt error | encryption mismatch — drop `--no-encrypt`, or disable AES on the board |
| attack sends but no `LIDAR TM` reply | widen `--listen`, confirm the OBC serial port, check the board is powered |
| spoof confirmed but no thruster fire | satellite is in safe/contingency — set an operational mission mode |
| `pio run` fails | missing RP2040 core/libs — see `Firmware/README.md` |

---

## 12. Safety, scope, and where to go next

**Safety / legal:** the `_rf.py` variants transmit real RF. Only transmit on
license-free ISM bands you're allowed to use, keep power low and sessions short,
and only ever against a FlatSat you own. See each RF script's header and
`Attacks/README.md`.

**Honest status:** the software pipeline and the CCSDS wire contract are tested
and verified byte-for-byte against the firmware; the on-board and on-air runs in
§§5–9 are the steps *you* close on real hardware — they have not been run on a
physical board in development.

**Extend the lab (knowledge goals):**
- Add **replay protection** to `SET_LIDAR_FRAME` and show the replay that it now
  blocks — a freshness/anti-replay lesson.
- Add a **variable-length frame** format and a matching bounds bug — a
  memory-corruption lesson on top of the current logic bugs.
- Make the autonomy **actually fuse**: require the IMU to corroborate motion
  before actuating, then show the same spoof failing — turning the vulnerable
  demo into the patched reference.
