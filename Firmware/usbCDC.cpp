/*  - usbCDC.cpp
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "usbCDC.h"
#include <Adafruit_TinyUSB.h>
#include <Arduino.h>

#define FRAME_HEADER_1 0xAA
#define FRAME_HEADER_2 0x55
#define HEADER_SIZE 4
#define MAX_FRAME_SIZE 1024

static uint8_t rx_buffer[MAX_FRAME_SIZE];
static size_t rx_len = 0;

#define BOARD_VERSION 0x0020 // Current version board 03/2026

Adafruit_USBD_CDC USBRadioLink;

static radioPacketReceivedCb usb_radio_cb = NULL;

void obcSetupUSB(void) {
  TinyUSBDevice.setID(0x239a, 0xcafe);
  TinyUSBDevice.setManufacturerDescriptor("Pwnsat");
  TinyUSBDevice.setProductDescriptor("Pwnsat - Flatsat");
  TinyUSBDevice.setSerialDescriptor("fsat");
  TinyUSBDevice.setDeviceVersion(BOARD_VERSION);
}

static void obcResetUSBStack(void) {
  if (TinyUSBDevice.mounted()) {
    TinyUSBDevice.detach();
    delay(10);
    TinyUSBDevice.attach();
  }
}

static void obcWaitConnectionCore0(void) {
  while (!Serial) {
    delay(1000);
  }
}

static void obcWaitConnectionCore1(void) {
  while (!USBRadioLink) {
    delay(1000);
  }
}

void obcConfigureCore0(void) {
  obcSetupUSB();

  Serial.begin(921600);
  obcWaitConnectionCore0();

  if (CFG_TUD_CDC < 2) {
    Serial.printf(
        "[WARNING] CFG_TUD_CDC must be at least 2, current value is %u\r\n",
        CFG_TUD_CDC);
    return;
  }
  Serial.printf("[INFO] USB Device configured successfully\r\n");
}

void obcConfigureCore1(void) {
  obcSetupUSB();
  USBRadioLink.begin(921600);
  obcResetUSBStack();
  obcWaitConnectionCore1();
}

void obcUSBPacketRecivedCallback(radioPacketReceivedCb recv_cb) {
  usb_radio_cb = recv_cb;
}

void obcUSBTransmitFrame(uint8_t *buffer, ssize_t buffer_len) {
  USBRadioLink.write(USB_LINK_SYNC_WORD);
  USBRadioLink.write(buffer, buffer_len);
}

static void printHexDump(const uint8_t *data, size_t len) {
  const size_t bytesPerLine = 32;
  char ascii[bytesPerLine + 1];
  ascii[bytesPerLine] = '\0';

  for (size_t i = 0; i < len; i++) {
    if (i % bytesPerLine == 0) {
      if (i != 0) {
        Serial.print("  |");
        Serial.println(ascii);
      }
      Serial.printf("%08X  ", (unsigned int)i);
    }

    Serial.printf("%02X ", data[i]);
    ascii[i % bytesPerLine] = (data[i] >= 32 && data[i] <= 126) ? data[i] : '.';
  }

  size_t remaining = len % bytesPerLine;
  if (remaining > 0) {
    for (size_t i = remaining; i < bytesPerLine; i++) {
      Serial.print("   ");
    }
  }

  Serial.print("  |");
  ascii[remaining == 0 ? bytesPerLine : remaining] = '\0';
  Serial.println(ascii);
}

void obcUSBRecv(void) {
  if (rx_len >= sizeof(rx_buffer)) {
    rx_len = 0;
  }

  while (USBRadioLink.available()) {
    size_t n =
        USBRadioLink.readBytes(rx_buffer + rx_len, sizeof(rx_buffer) - rx_len);
    rx_len += n;

    size_t offset = 0;
    while (rx_len - offset >= HEADER_SIZE) {
      uint8_t *p = &rx_buffer[offset];

      if (p[0] != FRAME_HEADER_1 || p[1] != FRAME_HEADER_2) {
        offset++;
        continue;
      }

      uint16_t len = (p[2] << 8) | p[3];
      size_t total = HEADER_SIZE + len;

      if (len > MAX_FRAME_SIZE || len == 0) {
        offset += 2;
        continue;
      }

      if (rx_len - offset < total) {
        break;
      }

      if (usb_radio_cb) {
        usb_radio_cb(&p[HEADER_SIZE], len);
        printHexDump(&p[HEADER_SIZE], len);
      }
      offset += total;
    }

    if (offset > 0) {
      memmove(rx_buffer, rx_buffer + offset, rx_len - offset);
      rx_len -= offset;
    }
  }
}