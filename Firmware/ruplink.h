/*  - rhandler.h
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#ifndef FIRMWARE_RUPLINK_H
#define FIRMWARE_RUPLINK_H
#include "regions.h"
#include <Arduino.h>

// UPLINK_FREQ_MHZ carries sub-MHz precision (float) for setFrequency();
// UPLINK_FREQ is the truncated integer MHz kept for the u16
// lastPayloadFrequency field and %u dashboard printouts.
#define UPLINK_FREQ_KHZ (FLATSAT_UPLINK_FREQ_KHZ)
#define UPLINK_FREQ_MHZ (FLATSAT_UPLINK_FREQ_KHZ / 1000.0f)
#define UPLINK_FREQ ((uint16_t)(FLATSAT_UPLINK_FREQ_KHZ / 1000))
#define UPLINK_BW (250)
#define UPLINK_SF (7)
#define UPLINK_CR (5)

typedef void (*radioPacketReceivedCb)(uint8_t *buffer, uint16_t buffer_len);

void uplinkRadioConfigure(void);
void uplinkRadioRegisterCb(radioPacketReceivedCb recv_cb);
void uplinkRadioCheckPacketReceived(void);
#endif // FIRMWARE_RUPLINK_H