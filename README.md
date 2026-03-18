# FlatSat 🛰️
The Hackable Satellite 

Flatsat v1.0 is a hardware based training platform designed to be vulnerable — on purpose. It’s built for hackers, engineers, and space enthusiasts who want to dive deep into space-grade systems, learn cybersecurity concepts, and prototype their own payloads.

### What You Can Do With Flatsat
- Hands-on Learning – Use Flatsat as the hardware companion to the PwnSat course, with structured lessons on binary exploitation, secure communication, reverse engineering, and space protocols.
- Hack Real Vulnerabilities – Explore and exploit firmware designed to simulate real-world satellite systems and vulnerabilities. It’s a safe playground for learning and discovery.
- Join the Mission CTF – Participate in space-themed capture-the-flag challenges that simulate real satellite operation scenarios. Your board becomes your spacecraft!
- Prototype Your Payloads – Use the onboard components to develop and test your own payload logic, radio communication, or telemetry systems before launching bigger projects.

Flatsat uses ISM (Industrial, Scientific, and Medical) band frequencies for all RF communication — typically 433 MHz or 915 MHz, depending on your region. These frequencies are internationally reserved for unlicensed, experimental, and educational use.

We do not use sensitive or restricted space communication bands like:

❌ X-band

❌ Ka-band

❌ S-band

This ensures that Flatsat does not interfere with any production space systems, licensed satellites, or critical ground infrastructure.

Flatsat is designed to help you learn and prototype radio systems safely and legally — all while gaining real-world skills in RF communication, signal analysis, and protocol fuzzing.

### Onboard Components
- RP2040 – Powerful MCU for comms and simulation.
- BME280 – Environmental sensor for telemetry testing.
- 2 x SX1262 – LoRa radios for realistic space-ground communication scenarios.
- Open Documentation – Github Wiki with Getting Started.
- LIS2DH – 3-axis accelerometer for sensor data emulation and tampering challenges.
- OpenHardware – Schematics and Firmware .

<p align=center>
    <a href="https://electroniccats.com/store/flatsat2/">
        <img src="https://github.com/ElectronicCats/flipper-shields/assets/44976441/0c617467-052b-4ab1-a3b9-ba36e1f55a91" width="200" height="104" />
    </a>
</p>

## Firmware

https://github.com/Pwnsat/FlatSat_Firmware

## Collaboration

[pwnsat.org](https://pwnsat.org/) and [flatsat.org](https://flatsat.org/)

## How to contribute <img src="https://electroniccats.com/wp-content/uploads/2018/01/fav.png" height="35"><img src="https://raw.githubusercontent.com/gist/ManulMax/2d20af60d709805c55fd784ca7cba4b9/raw/bcfeac7604f674ace63623106eb8bb8471d844a6/github.gif" height="30">

Contributions are welcome!

Please read the document [**Contribution manual**](https://github.com/ElectronicCats/electroniccats-cla/blob/main/electroniccats-contribution-manual.md) which will show you how to contribute your changes to the project.

✨ Thanks to all our [Contributors](https://github.com/ElectronicCats/Munchkin/graphs/contributors)! ✨

See [**_Electronic Cats CLA_**](https://github.com/ElectronicCats/electroniccats-cla/blob/main/electroniccats-cla.md) for more information.

See the [**Community code of conduct**](https://github.com/ElectronicCats/electroniccats-cla/blob/main/electroniccats-community-code-of-conduct.md) for a vision of the community we want to build and what we expect from it.

## License

Electronic Cats invests time and resources providing this open source design, please support Electronic Cats and open-source hardware by purchasing products from Electronic Cats!

Designed by Electronic Cats and PWNSAT.

Hardware released under an CERN Open Hardware Licence v1.2. See the LICENSE_HARDWARE file for more information.

Electronic Cats and PWNSAT is a registered trademark, please do not use if you sell these PCBs.
