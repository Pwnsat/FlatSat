# Flatsat 

Flatsat v1.0 is a hardware based training platform designed to be vulnerable — on purpose. It’s built for hackers, engineers, and space enthusiasts who want to dive deep into space-grade systems, learn cybersecurity concepts, and prototype their own payloads.

* [Hardware](##1.Hardware)
* [Firmware](##2.Firmware)
* [Subsystem Logic](##3.Subsystem_Logic_&_Workers)
* [Satellite Red Teaming OPS](##4.Satellite_Red_Teaming_OPS)

### What You Can Do With Flatsat
- Hands-on Learning – Use Flatsat as the hardware companion to the PwnSat course, with structured lessons on binary exploitation, secure communication, reverse engineering, and space protocols.
- Hack Real Vulnerabilities – Explore and exploit firmware designed to simulate real-world satellite systems and vulnerabilities. It’s a safe playground for learning and discovery.
- Join the Mission CTF – Participate in space-themed capture-the-flag challenges that simulate real satellite operation scenarios. Your board becomes your spacecraft!
- Prototype Your Payloads – Use the onboard components to develop and test your own payload logic, radio communication, or telemetry systems before launching bigger projects.

Flatsat uses ISM (Industrial, Scientific, and Medical) band frequencies for all RF communication — typically 433 MHz or 915 MHz, depending on your region. These frequencies are internationally reserved for unlicensed, experimental, and educational use.
❌ X-band
❌ Ka-band
❌ S-band
This ensures that Flatsat does not interfere with any production space systems, licensed satellites, or critical ground infrastructure.
Flatsat is designed to help you learn and prototype radio systems safely and legally — all while gaining real-world skills in RF communication, signal analysis, and protocol fuzzing.

## 1.Hardware
### Components
- **On-Board Computer**: RP2040
- **Command and Data Handling**: SX1262 (2)
- **Telemetry**: BME280
- **Position**: LIS2DH12
We do not use sensitive or restricted space communication bands like:

### Exposed Interfaces
- I2C
- UART
- SWD


## 2. Firmware

https://github.com/Pwnsat/FlatSat_Firmware

### 1. System Architecture

The firmware utilizes a **Asymmetric Multiprocessing (AMP)** approach on the RP2040 microcontroller. By splitting tasks across two cores, the system ensures that high-speed data links do not interfere with time-critical radio operations.

#### 1.1 Dual-Core Distribution
- **Core 0 (Mission Control & RF):** Manages the physical radio interfaces (Uplink/Downlink), sensor data acquisition, and the primary telemetry state machine.
- **Core 1 (OBC Data Link):** Dedicated to the TinyUSB stack, handling the `usbCDC` interface to provide a high-speed command-and-control link for the On-Board Computer (OBC) or ground station simulation.

> The OBC Data Link is used in case you don't have access to a SDR device to collect and send packets.

##1.2 Hardware Infrastructure

The infrastructure is designed for **FlatSat** testing, where hardware components are laid out for accessibility and auditing.

|**Component**|**Description**|**Interface**|
|---|---|---|
|**MCU**|Raspberry Pi RP2040|Dual Core ARM Cortex-M0+|
|**Radio 0**|SX1262 LoRa (Uplink)|SPI0 / NSS Pin 17|
|**Radio 1**|SX1262 LoRa (Downlink)|SPI0 / NSS Pin 5|
|**IMU**|LIS2DH12 Accelerometer|I2C (SDA 20, SCL 21)|
|**ENV**|BME280 Environment Sensor|I2C (SDA 20, SCL 21)|
|**Status**|WS2812B NeoPixel|GPIO 15|

# 2. Communication Protocol: Space Packet Protocol (SPP)

The core of the communication system is the **CCSDS Space Packet Protocol**. This allows the spacecraft to route data using **Application Process Identifiers (APIDs)**, enabling modular subsystem addressing.

## 2.1 Packet Encapsulation

Every packet consists of a **Primary Header** (6 bytes) and a **Data Field**.
1. **Packet Identification (2 bytes):** Contains the Version, Type (0 for TM, 1 for TC), and the APID.
2. **Packet Sequence Control (2 bytes):** Contains Segmentation Flags and the 14-bit Sequence Count.
3. **Packet Length (2 bytes):** Total length of the data field minus one.

## 2.2 APID Registry (Mission Control)

The firmware categorizes traffic into **Telecommands (TC)** and **Telemetry (TM)**:

|**APID**|**Function**|**Type**|**Payload Description**|
|---|---|---|---|
|`0x01`|PING|TC/TM|Connectivity heartbeat / ACK|
|`0x02`|RESET|TC|Triggers a hardware watchdog reboot|
|`0x04`|THRUSTER|TC/TM|Set/Get power levels for T0/T1|
|`0x07`|FLASH|TC/TM|Trigger fragmented image/firmware transfer|
|`0x08`|SEND_TM|TM|Standard periodic sensor telemetry frame|

---

## 3.Subsystem Logic & Workers

The firmware operates as a non-blocking state machine, governed by the `telemetryRadioWorker`.

#### 3.1 The Telemetry Worker

Instead of using `delay()`, the worker utilizes a `timeout_worker_t` structure to track intervals. This allows the system to remain responsive to incoming commands while managing multiple periodic tasks:

- **Sensor Telemetry:** Every 10.5 seconds.
- **Sync/Ping:** Every 15 seconds.
- **Idle Frame:** Every 20 seconds.

#### 3.2 Command Processing Flow

1. **Ingress:** Data arrives via `Radio 0` or `USB CDC`.
2. **Unpacking:** `spp_unpack_packet` validates the CCSDS header and checks for version/length consistency.
3. **Dispatch:** `commandApidHandler` matches the APID to a subsystem function.
4. **Execution:** The subsystem (e.g., `thruster.cpp`) updates its internal state.
5. **Feedback:** The system usually generates a TM response or blinks the LED to confirm action.

#### 4. Hardware Hacking Foundations: The Flash Worker

A unique feature for educational auditing is the `telemetrySPPTransmitFlash` routine. It simulates the transfer of a firmware image or large data block by fragmenting it into chunks.

- **Fragmentation:** Data is split into 16-byte segments.
- **Sequencing:** Packets are marked with `START`, `CONTINUE`, or `END` flags in the SPP header.
- **Integrity:** A custom `crc8_compute` is applied to each chunk to ensure data was not corrupted during RF transit.

### 5. Maintenance and Status Indicators

The NeoPixel LED provides real-time feedback for field operations without requiring a serial monitor.

|**Color**|**Pattern**|**Meaning**|
|---|---|---|
|**White**|Single Blink|Successful Downlink Transmission|
|**Blue**|Single Blink|Successful Uplink Reception|
|**Yellow**|8 Blinks|SPP Unpacking/Parsing Error|
|**Red**|8 Blinks|Hardware Interface / Radio Failure|
|**Red/Yellow**|Alternating|System Reboot Initiated|

---
### Compilation
This is the guide for compiling the actual firmware using Arduino platform.

**Board components**
- [Arduino Pico boards](https://github.com/earlephilhower/arduino-pico)

**Libraries**
- NeoPixelBus
- RadioLib
- SparkFun_LIS2DH12
- Adafruit_BME280
- Adafruit_TinyUSB
#### Board configuration
- **Board Type**: Generic RP20240
- Select the **Tools**:
	- **Board Stage**: IS25LP080 QSPI /4
	- **Flash Size**: 4 MB (No FS)
	- **USB Stack**: Adafruit TinyUSB

#### Flash firmware
- Sketch -> Verify/Compile
- Sketch -> Upload

Once the firmware successfully flashed the board, you will have now two serial endpoints.

---
## 6. Operational Attack Surface & Real-World Mapping

Modern satellites are no longer isolated systems; they are software-defined assets. The vulnerabilities identified in this firmware mirror historical "anomalies" and documented attacks on orbiting infrastructure.

### 7.1 RF Command Injection & Spoofing

Since the firmware lacks a Cryptographic Authentication layer (such as AES-GCM or HMAC-SHA256), the system is vulnerable to **Command Spoofing**.

- **The Attack:** An attacker uses a Software Defined Radio (SDR) to capture a legitimate "Telemetry" packet to identify the `SPACECRAFT_ID` and the current `Sequence Count`. They then craft a "Telecommand" packet with a valid APID (e.g., `0x04` for Thrusters) and transmit it at a higher power (Capture Effect) to the satellite.
- **Real-World Correlation:** In 1998, the **ROSAT** (Röntgen Satellite) was allegedly compromised via a ground station breach, where attackers sent commands to point the solar panels directly at the sun, eventually frying the batteries. While that was a network breach, the lack of command-level authentication on the RF link makes this firmware susceptible to the same outcome.

---

### 7.2 Intelligent RF Fuzzing (Protocol Mutation)

The firmware's dependency on `hexStringToBytes` and `spp_unpack_packet` makes it a prime target for **Protocol Fuzzing**.

- **The Attack:** Instead of random noise, an attacker performs "Grammar-based Fuzzing." They send valid CCSDS headers but mutate the length fields, the segmentation flags, and the APIDs. Specifically, sending a `START` flag without an `END` flag, or vice versa, can cause the `block_tx` logic in `worker.cpp` to hang or behave unpredictably.
- **Real-World Correlation:** Fuzzing the **NASA Core Flight System (cFS)** has revealed multiple memory corruption bugs in how the Space Packet Protocol is handled. By targeting the packet length vs. the actual payload received, attackers can trigger the "Integer Underflow" identified in the previous section.

---

### 7.3 Signal Jamming & Replay Attacks

The LoRa physical layer used in this card is resilient but not invincible.

- **The Attack:** * **DoS (Jamming):** Constant transmission on the `UPLINK_FREQ` prevents legitimate ground stations from reaching the satellite.
	- **Replay:** Capturing a "Reset" command (`APID 0x02`) and replaying it every time the satellite completes its boot sequence.
- **Real-World Correlation:** Radio Frequency Interference (RFI) is the most common "attack" in space. Whether intentional (Electronic Warfare) or unintentional (congested spectrum), the result is a Denial of Service. Replay attacks are particularly dangerous for satellites that do not implement a "Rolling Window" or "Timestamp" validation for commands.

---

### 7.4 "OBC-in-the-Middle" (USB Link Attack)

The dual-core architecture uses Core 1 as a USB-to-Radio bridge. If the On-Board Computer (OBC) or a connected payload is compromised, it can attack the firmware via the `usbCDC` interface.

- **The Attack:** A malicious payload on the satellite sends a malformed USB frame with `FRAME_HEADER_1` and `FRAME_HEADER_2`. By exploiting the `obcUSBRecv` logic, the payload can "Inject" commands directly into Core 0 as if they came from the Ground Station.
- **Real-World Correlation:** This mimics a **Supply Chain Attack**. If a third-party sensor or payload (e.g., a camera or scientific instrument) has a vulnerability, an attacker can use it as a pivot point to take control of the satellite's bus (OBC) and command the radios.
    

---

## 8. Summary of Attack Vectors

|**Attack Method**|**Layer**|**Tooling**|**Real-World Impact**|
|---|---|---|---|
|**Bit-Slipping**|Physical|SDR / GNU Radio|Desynchronization of the RF link.|
|**APID Brute-forcing**|Link|LoRa Transceiver|Discovery of hidden "Debug" commands.|
|**Telemetry Hijacking**|Data|Antenna / LNA|Eavesdropping on sensitive mission data.|
|**Logic Bombing**|Application|Custom Python Script|Triggering the `softwareReset()` loop.|

---

## Satellite Red Teaming OPS

## 1. Memory Corruption Vulnerabilities

### 1.1 Integer Underflow & Stack Buffer Overflow (APID: Broadcast)

In `worker.cpp`, the handler for `SPP_APID_TC_BROADCAST_MSG` contains a classic integer underflow leading to a massive buffer overflow.

```c++
void commandApidHandler(space_packet_t *space_packet) {
	uint16_t apid = space_packet->header.identification & 0x7FF;
	// ... 
		else if (apid == SPP_APID_TC_BROADCAST_MSG) {
			// No payload validation
			uint16_t frequency = ((uint16_t)space_packet->data[0] << 8) |
			(uint16_t)space_packet->data[1];
			size_t payload_total = space_packet->header.length + 1;
			size_t msg_len = payload_total - 2; // <- Vulnerability here
			uint8_t buffer_msg[SPP_MAX_PAYLOAD_CHUNK] = {0};
	//..
```


- **Why it happens:** The `header.length` is a 16-bit field controlled by the attacker. If the attacker sends a packet with `length = 0`, then `payload_total` becomes `1`. Subtracting `2` from an unsigned `size_t` results in an **underflow**, wrapping the value to `0xFFFFFFFF` (on a 32-bit system like RP2040).
- **Impact:** The `memcpy` will attempt to copy 4GB of data into a small 128-byte stack buffer (`buffer_msg`), leading to a stack smash, memory corruption, and potential **Remote Code Execution (RCE)**.
- **Exploitation:** Send an SPP packet with APID `0x06` and a CCSDS length field set to `0`. The RP2040 will crash or jump to an attacker-controlled address.

#### Exploit
```python
data = b"\x00"
header = SpHeader.tc(apid=0x06, seq_count=1, data_len=len(data) - 1)
packet = header.pack() + data

# Output
=========== Space Packet ===========
Version:            0
Type:               01 (TC)
Secondary Header:   0
APID:               0x0006
Sequence Flags:     0x3 (Unsegmented)
Sequence Count:     1
Data Length:        0
[HEADER]
00000000  10 06 C0 01 00 00                                 ......
[PAYLOAD]
00000000  00                                                .
```

## 2. Protocol & Logic Vulnerabilities

### 2.1 Lack of Authentication and Encryption (Command Injection)

The entire SPP implementation is "Cleartext." There is no cryptographic signature (MAC) or encryption on the Telecommands (TC).

- **Why it affects the mission:** Any actor with a LoRa-capable transceiver (like a Flipper Zero or an SX1262 dev board) can sniff the `DOWNLINK_FREQ` to see telemetry and then spoof packets on the `UPLINK_FREQ`.
- **Impact:** Full spacecraft takeover. An attacker can move thrusters, reset the clock, or flash malicious data.
- **Exploitation:** Use a LoRa SDR to replay a `SPP_APID_TC_RESETC` packet to keep the satellite in a permanent reboot loop.

### 2.2 Unauthenticated Remote Reset (DoS)

The `SPP_APID_TC_RESETC` command triggers a hardware watchdog reboot immediately.
```c
else if (apid == SPP_APID_TC_RESETC) {
	softwareReset(); // Calls watchdog_reboot
}
```


- **Impact:** Permanent Denial of Service. Because the system does not require a "key" or "sequence" to authorize a reset, a single packet can kill the mission.
- **Exploitation:** Broadcast the "Reset" APID packet periodically.

#### Exploit
```python
data = b"\x00"
header = SpHeader.tc(apid=0x02, seq_count=1, data_len=len(data) - 1)
packet = header.pack() + data

# Output
=========== Space Packet ===========
Version:            0
Type:               01 (TC)
Secondary Header:   0
APID:               0x0002
Sequence Flags:     0x3 (Unsegmented)
Sequence Count:     1
Data Length:        0
[HEADER]
00000000  10 02 C0 01 00 00                                 ......
[PAYLOAD]
00000000  00                                                .
None
```

## 3. Data Handling Vulnerabilities

### 3.1 Telemetry Leakage (Information Disclosure)

The `worker.cpp` sends high-resolution sensor data and internal states (thruster power, firmware versions) over the air unencrypted.

- **Impact:** An attacker can build a digital twin of the satellite, knowing exactly when it is moving or what its power levels are, aiding in timed physical attacks.

### 3.2 Double Decoding / Polyglot Packets

The system performs a strange "Double Decode." It receives a radio packet and then tries to parse the _binary content_ of that packet as an _ASCII Hex string_.

```c++
	uint8_t parsed[recvLen];
	size_t parsedLen = hexStringToBytes(byteArr, recvLen, parsed);
	radi_recv_cb(parsed, parsedLen);
```

- **Why it’s a vulnerability:** This introduces a "WAF-bypass" style vulnerability. If there were a security filter looking for specific binary command patterns, an attacker could encode those commands as ASCII Hex to bypass the filter, which the firmware then "helpfully" decodes back into the dangerous binary command.

## 4. Satellite Communication Vulnerabilities and Attacks

### 4.1 Eavesdropping Attack 



### 4.2 Command Injection Attack




### 4.3 Fuzzing Attack



### 4.4 Spoofing Attack




## 4. Summary

| **Vulnerability** | **Type** | **Complexity** | **Impact** |
| :--- | :--- | :--- | :--- |
| **Command Injection Attack** | Injection | Medium | **Critical (RCE)** |
| **Broadcast Underflow** | Memory Corruption | Medium | **Critical (RCE)** |
| **No Auth/Enc** | Broken Auth | Low | **Critical (Takeover)** |
| **Spoofing Attack** | Identity Theft | Medium | **Critical (Impersonation)** |
| **Unauthenticated Reset** | DoS | Low | High (Mission Loss) |
| **Fuzzing Attack** | Protocol/Input | Medium | High (DoS or Crash) |
| **Eavesdropping Attack** | Information Disclosure | Low | High (Data Leakage) |
| **Double Decoding** | Logic Flaw | Medium | Medium (Filter Bypass) |


## Collaboration

[pwnsat.org](https://pwnsat.org/) and [flatsat.org](https://flatsat.org/)
Contributions are welcome!

## How to contribute <img src="https://electroniccats.com/wp-content/uploads/2018/01/fav.png" height="35"><img src="https://raw.githubusercontent.com/gist/ManulMax/2d20af60d709805c55fd784ca7cba4b9/raw/bcfeac7604f674ace63623106eb8bb8471d844a6/github.gif" height="30">

Please read the document [**Contribution manual**](https://github.com/ElectronicCats/electroniccats-cla/blob/main/electroniccats-contribution-manual.md) which will show you how to contribute your changes to the project.

✨ Thanks to all our [Contributors](https://github.com/ElectronicCats/Munchkin/graphs/contributors)! ✨

See [**_Electronic Cats CLA_**](https://github.com/ElectronicCats/electroniccats-cla/blob/main/electroniccats-cla.md) for more information.

See the [**Community code of conduct**](https://github.com/ElectronicCats/electroniccats-cla/blob/main/electroniccats-community-code-of-conduct.md) for a vision of the community we want to build and what we expect from it.

## License

Electronic Cats invests time and resources providing this open source design, please support Electronic Cats and open-source hardware by purchasing products from Electronic Cats!

Designed by Electronic Cats and PWNSAT.

Hardware released under an CERN Open Hardware Licence v1.2. See the LICENSE_HARDWARE file for more information.

Electronic Cats and PWNSAT is a registered trademark, please do not use if you sell these PCBs.

# Special Thanks
A special thanks to **Alex Lynd**. His support made it possible to kick off the first version of the project, and his contribution remains a fundamental part of PwnSat. His work will always be embedded in what this project has become.