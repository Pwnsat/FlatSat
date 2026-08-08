/*  - thruster.cpp
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "thruster.h"
#include <Arduino.h>

typedef struct {
  uint8_t thruster0;
  uint8_t thruster0_state;
  uint8_t thruster1;
  uint8_t thruster1_state;
} thruster_context_t;

static thruster_context_t t_context = {
    .thruster0 = 10,
    .thruster0_state = THRUSTER_STATE_RUNNING,
    .thruster1 = 10,
    .thruster1_state = THRUSTER_STATE_RUNNING};

uint8_t thrusterGetT0Power(void) { return t_context.thruster0; }

uint8_t thrusterGetT1Power(void) { return t_context.thruster1; }

uint8_t thrusterGetT0State(void) { return t_context.thruster0_state; }

uint8_t thrusterGetT1State(void) { return t_context.thruster1_state; }

void thrusterSetT0Power(uint8_t power) {
  if (power > 0) {
    t_context.thruster0_state = THRUSTER_STATE_RUNNING;
  } else {
    t_context.thruster0_state = THRUSTER_STATE_IDLE;
  }
  t_context.thruster0 = power;
}

void thrusterSetT1Power(uint8_t power) {
  if (power > 0) {
    t_context.thruster1_state = THRUSTER_STATE_RUNNING;
  } else {
    t_context.thruster1_state = THRUSTER_STATE_IDLE;
  }
  t_context.thruster1 = power;
}

void thrusterSetT0State(uint8_t state) { t_context.thruster0_state = state; }

void thrusterSetT1State(uint8_t state) { t_context.thruster1_state = state; }