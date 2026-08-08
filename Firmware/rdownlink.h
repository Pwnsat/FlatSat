/*  - rdownlink.h
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#ifndef FIRMWARE_RDOWNLINK_H
#define FIRMWARE_RDOWNLINK_H
#include <Arduino.h>

#define DOWNLINK_FREQ (916)
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