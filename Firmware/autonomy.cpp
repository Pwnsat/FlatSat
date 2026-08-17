/*  - autonomy.cpp
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#include "autonomy.h"
#include "sensors.h"
#include "thruster.h"
#include <math.h>
#include <string.h>

static autonomy_state_t a_state;

void autonomyConfigure(void) {
  memset(&a_state, 0, sizeof(a_state));
  a_state.armed = false;
  a_state.action = AUTONOMY_ACTION_NONE;
}

static uint16_t autonomyImuMilliG(void) {
  float x = 0;
  float y = 0;
  float z = 0;
  float temp = 0;
  accelerometerRead(&x, &y, &z, &temp);
  const float magnitude = sqrtf((x * x) + (y * y) + (z * z));
  if (magnitude <= 0.0f) {
    return 0;
  }
  return magnitude > 65535.0f ? 65535 : (uint16_t)magnitude;
}

uint8_t autonomyEvaluate(const lidar_summary_t *lidar, bool armed) {
  a_state.armed = armed;
  a_state.imuMilliG = autonomyImuMilliG(); // "fusion": read the IMU...
  a_state.action = AUTONOMY_ACTION_NONE;
  a_state.thrusterCmd = 0;

  if (lidar == NULL) {
    a_state.hazard = false;
    return AUTONOMY_ACTION_NONE;
  }

  a_state.lidarMinMm = lidar->minMm;
  a_state.lidarCenterMm = lidar->centerMm;

  const bool lidar_valid = (lidar->status & LIDAR_STATUS_FRAME_VALID) != 0;
  const bool proximity_hazard = lidar_valid &&
                                lidar->minMm != LIDAR_DIST_INVALID &&
                                lidar->minMm < AUTONOMY_HAZARD_MM;
  a_state.hazard = proximity_hazard;

  if (!armed || !proximity_hazard) {
    return AUTONOMY_ACTION_NONE;
  }

  // INTENTIONAL VULNERABILITY (sensor-fusion poisoning):
  // The collision-avoidance decision is driven ENTIRELY by the LiDAR proximity
  // above. The IMU magnitude was read into a_state.imuMilliG as if it were
  // fused, but it never gates the maneuver -- there is no check that the
  // accelerometer corroborates real motion toward a hazard, no plausibility
  // bound, and no rate limit. Because the LiDAR summary is attacker-controlled
  // (Attacks/08_lidar_payload_spoof), a single spoofed "collision" frame makes
  // the spacecraft autonomously fire its avoidance thruster with no human
  // command and no independent sensor agreement. Fault-tolerant autonomy would
  // require multi-sensor consensus before actuating.
  thrusterSetT0Power(AUTONOMY_AVOID_THRUSTER_POWER);
  a_state.thrusterCmd = AUTONOMY_AVOID_THRUSTER_POWER;
  a_state.action = AUTONOMY_ACTION_THRUSTER;
  a_state.triggerCount++;
  a_state.lastTriggerMs = millis();
  return a_state.action;
}

bool autonomyRead(autonomy_state_t *out) {
  if (out == NULL) {
    return false;
  }
  *out = a_state;
  return true;
}

uint16_t autonomySecondsSinceTrigger(void) {
  if (a_state.triggerCount == 0) {
    return 0xFFFF;
  }
  const unsigned long seconds = (millis() - a_state.lastTriggerMs) / 1000UL;
  return seconds > 0xFFFF ? 0xFFFF : (uint16_t)seconds;
}
