/*  - spacecan.h
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Software-simulated SpaceCAN bus console, ported from spacecan_lib's frame
 * format and reassembly logic. Reachable only through the existing debug
 * Serial console via a text command toggle (no new USB endpoint, no changes
 * to the SPP/radio command path).
 */
#ifndef FIRMWARE_SPACECAN_H
#define FIRMWARE_SPACECAN_H
#include <Arduino.h>

#define SC_MAX_FRAGMENTS 43
#define SC_MAX_PACKET_SIZE 256
#define SC_MAX_DATA_LEN 8
#define SC_PAYLOAD_HEADER_LEN 2
#define SC_MAX_CHUNK_LEN (SC_MAX_DATA_LEN - SC_PAYLOAD_HEADER_LEN)
#define SC_REASSEMBLY_TIMEOUT_MS 500

#define SC_CAN_FUNCTION_MASK 0x780
#define SC_CAN_NODE_MASK 0x07F
#define SC_CANID_REQ 0x280
#define SC_CANID_REP 0x300

#define SC_STATE_INIT 0x00
#define SC_STATE_OPERATIONAL 0x01
#define SC_STATE_ERROR 0x09

#define SC_NODE_SENSOR 0x01
#define SC_NODE_MOTOR 0x04
#define SC_NODE_BATTERY 0x07

typedef struct {
  uint32_t can_id;
  uint8_t dlc;
  uint8_t buffer[SC_MAX_DATA_LEN];
} spacecan_frame_t;

void consoleWorker(void);
bool consoleSensorModeActive(void);
bool consoleSpacecanModeActive(void);

#endif // FIRMWARE_SPACECAN_H
