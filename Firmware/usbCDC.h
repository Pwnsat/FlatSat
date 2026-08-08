/*  - usbCDC.h
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#ifndef FIRMWARE_USBCDC_H
#define FIRMWARE_USBCDC_H
#include "ruplink.h"

#define USB_LINK_SYNC_WORD 0xAA

void obcSetupUSB(void);
void obcConfigureCore0(void);
void obcConfigureCore1(void);

void obcUSBTransmitFrame(uint8_t *buffer, ssize_t buffer_len);
void obcUSBRecv(void);
void obcUSBPacketRecivedCallback(radioPacketReceivedCb recv_cb);
#endif // FIRMWARE_USBCDC_H
