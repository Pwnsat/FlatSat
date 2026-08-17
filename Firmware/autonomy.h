/*  - autonomy.h
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#ifndef FIRMWARE_AUTONOMY_H
#define FIRMWARE_AUTONOMY_H
#include <Arduino.h>
#include "lidar.h"

/* Collision-avoidance autonomy: an onboard hazard response that reacts to the
 * LiDAR payload's proximity reading. It is meant to "fuse" the LiDAR range
 * with the IMU before actuating, but (by design, see autonomyEvaluate) it does
 * not -- the maneuver is driven by the attacker-controllable LiDAR summary
 * alone. This is the sensor-fusion-poisoning teaching surface: a spoofed
 * proximity (Attacks/08_lidar_payload_spoof) triggers a real thruster burn.
 */

#define AUTONOMY_HAZARD_MM 500 /* proximity (mm) that trips avoidance */
#define AUTONOMY_AVOID_THRUSTER_POWER 200

#define AUTONOMY_ACTION_NONE 0x00
#define AUTONOMY_ACTION_THRUSTER 0x01

typedef struct {
  bool armed;           /* autonomy active in the current mission mode      */
  bool hazard;          /* proximity below the hazard threshold             */
  uint16_t lidarMinMm;  /* proximity that drove the decision                */
  uint16_t lidarCenterMm;
  uint16_t imuMilliG;   /* fused IMU magnitude -- recorded, NOT cross-checked */
  uint8_t action;       /* AUTONOMY_ACTION_*                                */
  uint8_t thrusterCmd;  /* avoidance thruster power commanded               */
  uint16_t triggerCount;
  unsigned long lastTriggerMs;
} autonomy_state_t;

void autonomyConfigure(void);
/* Evaluate the LiDAR summary and, if armed and a hazard is seen, actuate.
 * Returns the AUTONOMY_ACTION_* taken. */
uint8_t autonomyEvaluate(const lidar_summary_t *lidar, bool armed);
bool autonomyRead(autonomy_state_t *out);
uint16_t autonomySecondsSinceTrigger(void); /* 0xFFFF if never */

#endif // FIRMWARE_AUTONOMY_H
