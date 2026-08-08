/*  - secure_link.h
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#ifndef FIRMWARE_SECURE_LINK_H
#define FIRMWARE_SECURE_LINK_H
#include "spp.h"
#include <Arduino.h>

#define SECURE_LINK_AES_KEY_SIZE 16

bool secureLinkIsEnabled(void);
void secureLinkSetEnabled(bool enabled);
const uint8_t *secureLinkKeyBytes(void);
size_t secureLinkKeySize(void);
bool secureLinkEncodePayload(const uint8_t *input, uint16_t input_len,
                             uint8_t *output, uint16_t *output_len);
bool secureLinkDecodePayload(const uint8_t *input, uint16_t input_len,
                             uint8_t *output, uint16_t *output_len);

#endif // FIRMWARE_SECURE_LINK_H
