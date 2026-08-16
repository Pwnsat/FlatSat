/*  - lidar.cpp
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#include "lidar.h"
#include <Arduino.h>
#include <string.h>

typedef struct {
  bool present;
  lidar_summary_t summary;
  uint16_t ingestCount;
  unsigned long lastIngestMs;
} lidar_context_t;

static lidar_context_t l_context;

static uint16_t lidarReadU16LE(const uint8_t *p) {
  return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t lidarReadU32LE(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

void lidarConfigure(void) {
  memset(&l_context, 0, sizeof(l_context));
  l_context.present = false;
  Serial.println("[INFO] LiDAR payload subsystem ready (host-bridge)");
}

/* Summary block layout (little-endian), matching
 * Payloads/lidar/tau_lidar_payload.py encode_summary():
 *   [0]      frameType   u8
 *   [1..2]   minMm       u16
 *   [3..4]   maxMm       u16
 *   [5..6]   meanMm      u16
 *   [7..8]   centerMm    u16
 *   [9]      validPct    u8
 *   [10..11] amplitude   u16
 *   [12..13] width       u16
 *   [14..15] height      u16
 *   [16..19] frameCount  u32
 *   [20]     status      u8
 */
bool lidarIngestSummary(const uint8_t *data, uint16_t len) {
  if (data == NULL || len < LIDAR_SUMMARY_WIRE_LEN) {
    return false;
  }

  lidar_summary_t s;
  s.frameType = data[0];
  s.minMm = lidarReadU16LE(&data[1]);
  s.maxMm = lidarReadU16LE(&data[3]);
  s.meanMm = lidarReadU16LE(&data[5]);
  s.centerMm = lidarReadU16LE(&data[7]);
  s.validPct = data[9];
  s.amplitude = lidarReadU16LE(&data[10]);
  s.width = lidarReadU16LE(&data[12]);
  s.height = lidarReadU16LE(&data[14]);
  s.frameCount = lidarReadU32LE(&data[16]);
  s.status = data[20];

  l_context.summary = s;
  l_context.present = true;
  l_context.ingestCount++;
  l_context.lastIngestMs = millis();
  return true;
}

bool lidarRead(lidar_summary_t *out) {
  if (out == NULL || !l_context.present) {
    return false;
  }
  *out = l_context.summary;
  return true;
}

bool lidarHasFix(void) {
  return l_context.present &&
         (l_context.summary.status & LIDAR_STATUS_FRAME_VALID);
}

uint16_t lidarIngestCount(void) { return l_context.ingestCount; }

uint16_t lidarSecondsSinceLast(void) {
  if (!l_context.present) {
    return 0xFFFF;
  }
  const unsigned long seconds = (millis() - l_context.lastIngestMs) / 1000UL;
  return seconds > 0xFFFF ? 0xFFFF : (uint16_t)seconds;
}
