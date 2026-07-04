<div align="center">

<img src="https://raw.githubusercontent.com/wiki/Pwnsat/FlatSat/flatsat-wiki-banner.png" alt="FlatSat Satellite Security Research Platform Banner" width="100%">

# FlatSat v1.0

**The world’s first open-source and hardware platform vulnerable-by-design, engineered specifically to learn space hacking adn aerospace cybersecurity.**

</div>

---

## Welcome to FlatSat

FlatSat is a hardware-based training platform designed to be vulnerable on purpose. It is built for hackers, engineers, and space enthusiasts who want to dive deep into space-grade systems, learn cybersecurity concepts, and prototype their own payloads in a safe, controlled environment.

The project simulates critical real-world satellite subsystems, orbital telemetry, and authentic aerospace communication protocols, serving as a bridge between hardware hacking and aerospace security research.

---

## What You Can Do With FlatSat

* **Hands-on Learning:** Use FlatSat as the hardware companion to your aerospace cybersecurity studies, featuring lessons on binary exploitation, secure communication, reverse engineering, and space protocols.
* **Hack Real Vulnerabilities:** Explore and exploit firmware designed to simulate historical or realistic software failures in orbiting infrastructure.
* **Join Space CTFs:** Participate in space-themed Capture The Flag challenges that simulate real satellite operation scenarios, turning your board into your own spacecraft.
* **Prototype Your Payloads:** Use the onboard components to develop and test your own payload logic, radio communication, or telemetry systems before deploying larger projects.

---

## Hardware Overview

FlatSat's physical architecture layout is fully accessible and designed for open hardware auditing:

* **On-Board Computer (OBC):** Powered by the dual-core Raspberry Pi RP2040 microcontroller.
* **Dual RF Link Subsystem:** Equipped with two independent Semtech SX1262 sub-GHz LoRa modules dedicated to Uplink (receive) and Downlink (transmit) configurations.
* **Onboard Sensors:** Features a BME280 environmental sensor and a LIS2DH12 3-axis accelerometer to emulate real spatial telemetry.
* **Exposed Auditing Interfaces:** Physical header connector breakouts for direct bus monitoring via UART, I2C, and SWD debug lines.

> **RF Compliance Note:** FlatSat operates exclusively within standard license-free ISM bands (typically 433 MHz or 915 MHz depending on your region). This ensures a legal, safe educational ecosystem that does not interfere with production space systems or critical ground infrastructure.

---

## Technical Documentation and Guides (Wiki)

All deep technical documentation, source analysis, and setup guides have been centralized. If you want to start compiling, debugging, or exploiting the platform, please visit the [FlatSat Wiki](https://github.com/Pwnsat/FlatSat/wiki):

* **[01. Quick Start Guide](https://github.com/Pwnsat/FlatSat/wiki/Getting-Started):** Toolchain setup, compiling the firmware, flashing the RP2040, and verifying hardware operations.
* **[02. Hardware Anatomy](https://github.com/Pwnsat/FlatSat/wiki/Hardware-Anatomy-&-Specifications):** Physical layout, schematics, pinouts, and hardware debugging ports.
* **[03. Core Firmware Architecture](https://github.com/Pwnsat/FlatSat/wiki/Firmware-&-System-Architecture):** Deep dive into the Asymmetric Multiprocessing (AMP) architecture dividing tasks across Core 0 and Core 1.
* **[04. Space Packet Protocol (CCSDS)](https://github.com/Pwnsat/FlatSat/wiki/Space-Packet-Protocol---CCSDS):** Aerospace framing standards, packet encapsulation structure, and the active APID registry.
* **[05. Offensive Attack Vectors](https://github.com/Pwnsat/FlatSat/wiki/Satellite-Hacking-&-Attack-Vectors):** The security playground. Explaining packet fuzzing, telecommand spoofing, buffer overflows, and unauthorized subsystem manipulation.

---

## Collaboration and Community

This project is an open-source initiative maintained by PWNSAT and Electronic Cats. Contributions are highly welcome.


## License

Electronic Cats invests time and resources providing this open source design, please support Electronic Cats and open-source hardware by purchasing products from Electronic Cats!

Designed by PWNSAT and Electronic Cats.

Hardware released under an CERN Open Hardware Licence v1.2. See the LICENSE_HARDWARE file for more information.

PWNSAT and Electronic Cats are a registered trademark, please do not use if you sell these PCBs.

# Special Thanks
A special thanks to **Alex Lynd**. His support made it possible to kick off the first version of the project, and his contribution remains a fundamental part of PWNSAT. His work will always be embedded in what this project has become.

