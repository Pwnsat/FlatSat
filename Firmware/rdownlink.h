/*  - rdownlink.h
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#ifndef FIRMWARE_RDOWNLINK_H
#define FIRMWARE_RDOWNLINK_H
#include "regions.h"
#include <Arduino.h>

// DOWNLINK_FREQ_MHZ carries sub-MHz precision (float) for setFrequency();
// DOWNLINK_FREQ is the truncated integer MHz kept for the u16
// lastPayloadFrequency field and %u dashboard printouts.
#define DOWNLINK_FREQ_KHZ (FLATSAT_DOWNLINK_FREQ_KHZ)
#define DOWNLINK_FREQ_MHZ (FLATSAT_DOWNLINK_FREQ_KHZ / 1000.0f)
#define DOWNLINK_FREQ ((uint16_t)(FLATSAT_DOWNLINK_FREQ_KHZ / 1000))
#define DOWNLINK_BW (250)
#define DOWNLINK_SF (7)
#define DOWNLINK_CR (5)

void downlinkRadioConfigure(void);
bool downlinkRadioTransmit(uint8_t *buffer, uint16_t buffer_len);
void downlinkRadioTransmitNBlock(uint8_t *buffer, uint16_t buffer_len);
bool downlinkRadioTransmitBroadcast(uint16_t frequency, uint8_t *buffer,
                                    uint16_t buffer_len);
void downlinkRadioCheckTransmition(void);
#endif // FIRMWARE_RDOWNLINK_H