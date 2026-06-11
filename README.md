<p align="center">
  <img src="https://raw.githubusercontent.com/Pwnsat/FlatSat/main/assets/flatsat-banner.png" alt="FlatSat Banner" width="600">
</p>

<h1 align="center">FlatSat v1.0</h1>

<p align="center">
  <strong>An open-source, deliberately vulnerable hardware platform for satellite cybersecurity training and firmware prototyping.</strong>
</p>

<p align="center">
  <a href="https://github.com/Pwnsat/FlatSat/blob/main/LICENSE"><img src="https://img.shields.io/github/license/Pwnsat/FlatSat?style=flat-square" alt="License"></a>
  <a href="https://github.com/Pwnsat/FlatSat/stargazers"><img src="https://img.shields.io/github/stars/Pwnsat/FlatSat?style=flat-square" alt="Stars"></a>
  <a href="https://github.com/Pwnsat/FlatSat/issues"><img src="https://img.shields.io/github/issues/Pwnsat/FlatSat?style=flat-square" alt="Issues"></a>
</p>

---

FlatSat is a low-cost, dual-core educational platform designed to simulate the architecture, communications, and potential vulnerabilities of a real satellite CubeSat. Powered by the RP2040 MCU and equipped with independent dual LoRa transceivers, FlatSat allows security researchers, students, and aerospace enthusiasts to experiment with satellite sub-system hacking, telemetry fuzzing, and space protocol analysis.

> [!WARNING]
> **Educational & Security Research Purposes Only:** FlatSat operates within standard ISM bands (433 MHz / 915 MHz). Users must comply with their local telecommunications regulations regarding RF transmission power and licensing.

---

## Key Features

* **Dual-Core Architecture (AMP):** Simulates real satellite task isolation. Core 0 handles critical Mission Control and RF telemetry, while Core 1 manages USB CDC data streams.
* **Dual Radio Transceivers:** Features two independent SX1262 LoRa modules dedicated to isolated Uplink (TC) and Downlink (TM) channels.
* **On-Board Environmental Telemetry:** Integrated BME280 (temperature/pressure/humidity) and LIS2DH12 (3-axis accelerometer) sensors for realistic telemetry simulation.
* **Space-Grade Communications:** Implements the **CCSDS Space Packet Protocol**, providing students with hands-on experience in real aerospace packet framing and validation.
* **Multi-Transport Support:** Fully functional over-the-air (OTA) via RF/SDR or through local USB serial emulation.

---

## 📖 Getting Started & Documentation

The complete documentation, including hardware schematics, firmware breakdown, and exploitation guides, is located in the **GitHub Wiki**.

### [➔ Explore the FlatSat Wiki](https://github.com/Pwnsat/FlatSat/wiki)

* **[Hardware Specifications](https://github.com/Pwnsat/FlatSat/wiki/01.-Hardware-Anatomy-&-Specifications)** - Board anatomy, pinouts, and components.
* **[Firmware Architecture](https://github.com/Pwnsat/FlatSat/wiki/02.-Firmware-&-System-Architecture)** - AMP core distribution and non-blocking worker logistics.
* **[CCSDS Protocol Details](https://github.com/Pwnsat/FlatSat/wiki/03.-Space-Packet-Protocol---CCSDS)** - Telecommand (TC) and Telemetry (TM) packet structures and APID mapping.

---

## Repository Structure

```text
├── assets/             # Images and media assets
├── firmware/           # RP2040 C/C++ source code
│   ├── src/            # Core subsystems (telemetry, thruster, etc.)
│   └── include/        # CCSDS headers and configuration definitions
├── hardware/           # KiCad schematics and PCB layout files
└── README.md           # This file
