/*  - thruster.h
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#ifndef FIRMWARE_THRUSTER_H
#define FIRMWARE_THRUSTER_H
#include <Arduino.h>

typedef enum { THRUSTER_STATE_IDLE, THRUSTER_STATE_RUNNING } thruster_state_t;

uint8_t thrusterGetT0Power(void);
uint8_t thrusterGetT1Power(void);

uint8_t thrusterGetT0State(void);
uint8_t thrusterGetT1State(void);

void thrusterSetT0Power(uint8_t power);
void thrusterSetT1Power(uint8_t power);

void thrusterSetT0State(uint8_t state);
void thrusterSetT1State(uint8_t state);

#endif // FIRMWARE_THRUSTER_H