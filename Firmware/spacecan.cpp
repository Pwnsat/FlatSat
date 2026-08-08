/*  - spacecan.cpp
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Software-simulated SpaceCAN bus console, ported from spacecan_lib's frame
 * format and reassembly logic, extended with two additional documented CAN
 * bus vulnerability classes so the demo covers three distinct, real,
 * published attack techniques against CAN-based satellite buses:
 *
 *   1) No message/node origin authentication (finding #23, ported from
 *      spacecan_lib as-is). Documented broadly against CAN-based CubeSat
 *      buses -- the protocol has no native authentication or encryption.
 *
 *   2) Arbitration/flood denial of service. CAN resolves bus contention by
 *      letting the numerically lowest CAN ID always win arbitration.
 *      Flooding the bus with high-priority (low ID) traffic starves
 *      legitimate lower-priority traffic. Simulated here using the two
 *      existing CAN ID families (request 0x280+ outranks reply 0x300+).
 *
 *   3) Bus-off attack. The CAN 2.0 protocol silently disconnects
 *      ("bus-off") any node whose transmit/receive error counter exceeds
 *      255, a mechanism intended for fault containment that has been shown
 *      (automotive CAN security research) to be abusable to force a
 *      targeted, valid node offline using only malformed/erroneous frames,
 *      without ever forging a legitimate command. Simulated per node here.
 *
 * Console is text-based over the existing debug Serial port, reachable via
 * the "2" menu key. Printed as a plain scrolling list (color-coded per
 * node with ANSI SGR codes only, no cursor positioning) each time the
 * view is refreshed on demand.
 */
#include "spacecan.h"
#include "sensors.h"
#include "thruster.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SC_ERROR_INCREMENT 8
#define SC_BUS_OFF_THRESHOLD 256

#define SC_FLOOD_WINDOW_MS 1000
#define SC_FLOOD_SAMPLE_COUNT 5

#define ANSI_RESET "\x1b[0m"
#define ANSI_GREEN "\x1b[32m"
#define ANSI_RED "\x1b[31m"
#define ANSI_YELLOW "\x1b[33m"
#define ANSI_CYAN "\x1b[36m"
#define ANSI_MAGENTA "\x1b[35m"

typedef struct {
  uint8_t active;
  uint8_t total_frames;
  uint32_t last_can_id;
  uint8_t last_seq;
  uint8_t received_mask[SC_MAX_FRAGMENTS];
  uint8_t fragment_sizes[SC_MAX_FRAGMENTS];
  uint8_t buffer[SC_MAX_PACKET_SIZE];
  uint32_t last_update_ms;
} spacecan_reassembly_ctx_t;

typedef struct {
  uint8_t node_id;
  const char *name;
  uint16_t error_count;
  bool bus_off;
} sc_node_state_t;

typedef enum {
  CONSOLE_MODE_MENU = 0,
  CONSOLE_MODE_SENSORS = 1,
  CONSOLE_MODE_SPACECAN = 2,
  CONSOLE_MODE_IDLE = 3,
} console_mode_t;

static spacecan_reassembly_ctx_t s_reassembly = {0};
static console_mode_t s_mode = CONSOLE_MODE_MENU;
static bool s_hint_printed = false;
static uint8_t s_battery_charge = 80;
static unsigned long s_last_status_ms = 0;
static char s_line_buf[128];
static size_t s_line_len = 0;

static sc_node_state_t s_nodes[3] = {
    {SC_NODE_MOTOR, "MOTOR", 0, false},
    {SC_NODE_BATTERY, "BATTERY", 0, false},
    {SC_NODE_SENSOR, "SENSOR", 0, false},
};

static unsigned long s_recent_frames[SC_FLOOD_SAMPLE_COUNT] = {0};
static uint8_t s_recent_frame_idx = 0;
static uint8_t s_recent_frame_count = 0;
static bool s_bus_congested = false;

/* ---------- Node lookup ---------- */

static sc_node_state_t *scFindNode(uint8_t node_id) {
  for (uint8_t i = 0; i < 3; i++) {
    if (s_nodes[i].node_id == node_id) {
      return &s_nodes[i];
    }
  }
  return NULL;
}

/* ---------- Reassembly (finding #26/#27/#28, ported as-is) ---------- */

static void scReassemblyReset(spacecan_reassembly_ctx_t *ctx) {
  ctx->active = 0;
  memset(ctx->received_mask, 0, sizeof(ctx->received_mask));
}

static int scReassemblyPackets(spacecan_reassembly_ctx_t *ctx,
                               const spacecan_frame_t *frame, uint32_t now_ms,
                               uint8_t *out_buffer, size_t *out_len) {
  if (frame->dlc < 2) {
    return -1;
  }

  uint8_t total = frame->buffer[0] + 1;
  uint8_t seq = frame->buffer[1];

  if (total == 0 || total > SC_MAX_FRAGMENTS) {
    return -1;
  }

  if (!ctx->active) {
    ctx->active = 1;
    ctx->total_frames = total;
    memset(ctx->received_mask, 0, sizeof(ctx->received_mask));
  }

  if (now_ms - ctx->last_update_ms > SC_REASSEMBLY_TIMEOUT_MS) {
    scReassemblyReset(ctx);
  }

  if (seq >= ctx->total_frames) {
    return -1;
  }

  size_t payload_len = frame->dlc - SC_PAYLOAD_HEADER_LEN;

  if (frame->can_id == ctx->last_can_id && frame->buffer[1] == ctx->last_seq) {
    return 0;
  }

  /* No check that frame->can_id matches the can_id of earlier fragments in
   * this session (finding #27), and no bound on
   * seq * SC_MAX_CHUNK_LEN + payload_len against sizeof(ctx->buffer)
   * (finding #26) -- intentionally mirrors the reference implementation. */
  ctx->last_can_id = frame->can_id;
  ctx->last_seq = frame->buffer[1];
  ctx->last_update_ms = now_ms;
  ctx->received_mask[seq] = 1;
  ctx->fragment_sizes[seq] = payload_len;

  size_t offset = seq * SC_MAX_CHUNK_LEN;
  memcpy(&ctx->buffer[offset], &frame->buffer[SC_PAYLOAD_HEADER_LEN], payload_len);

  size_t final_size = 0;
  for (uint8_t i = 0; i < ctx->total_frames; i++) {
    if (!ctx->received_mask[i]) {
      return 0;
    }
    final_size += ctx->fragment_sizes[i];
  }

  memcpy(out_buffer, ctx->buffer, final_size);
  *out_len = final_size;
  scReassemblyReset(ctx);
  return 1;
}

/* ---------- Vulnerability #2: arbitration/flood DoS ---------- */

static void scTrackFrameRate(void) {
  const unsigned long now = millis();
  s_recent_frames[s_recent_frame_idx] = now;
  s_recent_frame_idx = (uint8_t)((s_recent_frame_idx + 1) % SC_FLOOD_SAMPLE_COUNT);

  uint8_t count_in_window = 0;
  for (uint8_t i = 0; i < SC_FLOOD_SAMPLE_COUNT; i++) {
    if (s_recent_frames[i] != 0 && (now - s_recent_frames[i]) <= SC_FLOOD_WINDOW_MS) {
      count_in_window++;
    }
  }
  s_recent_frame_count = count_in_window;
  s_bus_congested = (count_in_window >= SC_FLOOD_SAMPLE_COUNT);
}

/* ---------- Vulnerability #3: bus-off attack ---------- */

static void scDispatchFrame(const spacecan_frame_t *frame) {
  const uint16_t function = frame->can_id & SC_CAN_FUNCTION_MASK;
  const uint8_t node_id = frame->can_id & SC_CAN_NODE_MASK;

  if (function != SC_CANID_REQ) {
    Serial.printf("[SPACECAN] reply-family frame for node 0x%02X (no action)\r\n",
                  node_id);
    return;
  }

  sc_node_state_t *node = scFindNode(node_id);
  if (node == NULL) {
    Serial.printf("[SPACECAN] frame targets unknown node 0x%02X, ignored\r\n",
                  node_id);
    return;
  }

  if (node->bus_off) {
    Serial.printf(
        "[SPACECAN] node 0x%02X is BUS-OFF (silently disconnected), frame dropped\r\n",
        node_id);
    return;
  }

  if (frame->dlc < 2 || frame->buffer[0] != 0x01) {
    /* Malformed/unrecognized command -- treated as a CAN protocol error.
     * Real CAN controllers add 8 to the transmit/receive error counter per
     * error; once it reaches 256 the node is forced into bus-off and
     * disconnects itself from the bus (CAN 2.0 spec, TEC/REC mechanism).
     * This lets an attacker silence a specific node without ever sending
     * it a single valid/authenticated command. */
    node->error_count = (uint16_t)(node->error_count + SC_ERROR_INCREMENT);
    Serial.printf("[SPACECAN] node 0x%02X protocol error (err_count=%u/%u)\r\n",
                  node_id, node->error_count, SC_BUS_OFF_THRESHOLD);
    if (node->error_count >= SC_BUS_OFF_THRESHOLD) {
      node->bus_off = true;
      Serial.printf(
          "[SPACECAN] node 0x%02X entered BUS-OFF -- silently disconnected (DoS)\r\n",
          node_id);
    }
    return;
  }

  node->error_count = 0; /* a valid frame clears the error counter, matching
                          * real CAN controller behavior */

  /* No check that this frame actually originated from node 0 (controller) --
   * finding #23. Any injected request-family frame is trusted by node_id
   * alone. */
  if (node_id == SC_NODE_MOTOR) {
    thrusterSetT0Power(frame->buffer[1]);
    Serial.printf(
        "[SPACECAN] MOTOR node 0x%02X accepted: thruster0 power = %u (no origin check)\r\n",
        node_id, frame->buffer[1]);
  } else if (node_id == SC_NODE_BATTERY) {
    s_battery_charge = frame->buffer[1];
    Serial.printf(
        "[SPACECAN] BATTERY node 0x%02X accepted: charge = %u%% (no origin check)\r\n",
        node_id, frame->buffer[1]);
  } else {
    Serial.printf("[SPACECAN] SENSOR node 0x%02X has no writable commands\r\n",
                  node_id);
  }
}

/* ---------- Fixed-position panel ---------- */

static void scPrintBar(size_t width) {
  char bar[96];
  if (width > sizeof(bar) - 1) {
    width = sizeof(bar) - 1;
  }
  memset(bar, '=', width);
  bar[width] = '\0';
  Serial.println(bar);
}

static void scPrintStatus(void) {
  float acc_x = 0, acc_y = 0, acc_z = 0, acc_t = 0;
  float bme_t = 0, bme_p = 0, bme_alt = 0, bme_h = 0;
  accelerometerRead(&acc_x, &acc_y, &acc_z, &acc_t);
  bmeRead(&bme_t, &bme_p, &bme_alt, &bme_h);

  /* Build every line as plain text first (no ANSI codes) so its length can
   * be measured accurately -- color escape sequences would otherwise
   * corrupt the width calculation used for the top/bottom bars. */
  const char *title = "--- SPACECAN BUS MONITOR (SIMULATED, IN-FIRMWARE) ---";
  char line_motor[96];
  char line_battery[96];
  char line_sensor[96];
  char line_bus[96];
  char line_reasm[96];
  const char *line_cmds =
      "Commands: SC INJECT <id_hex> <bytes...> | SC STATUS | SC RESET <id_hex> | M";

  snprintf(line_motor, sizeof(line_motor),
          "MOTOR   (0x%02X) %-11s thruster0=%-3u thruster1=%-3u err=%u/%u",
          SC_NODE_MOTOR, s_nodes[0].bus_off ? "BUS-OFF" : "OPERATIONAL",
          thrusterGetT0Power(), thrusterGetT1Power(), s_nodes[0].error_count,
          SC_BUS_OFF_THRESHOLD);

  snprintf(line_battery, sizeof(line_battery),
          "BATTERY (0x%02X) %-11s charge=%-3u%% err=%u/%u", SC_NODE_BATTERY,
          s_nodes[1].bus_off ? "BUS-OFF" : "OPERATIONAL", s_battery_charge,
          s_nodes[1].error_count, SC_BUS_OFF_THRESHOLD);

  snprintf(line_sensor, sizeof(line_sensor),
          "SENSOR  (0x%02X) %-11s temp=%.1fC hum=%.1f%% accel=%.0f/%.0f/%.0f err=%u/%u",
          SC_NODE_SENSOR, s_nodes[2].bus_off ? "BUS-OFF" : "OPERATIONAL",
          bme_t, bme_h, acc_x, acc_y, acc_z, s_nodes[2].error_count,
          SC_BUS_OFF_THRESHOLD);

  snprintf(line_bus, sizeof(line_bus), "Bus arbitration: %s frames/1s=%u",
          s_bus_congested ? "CONGESTED (reply-family frames losing arbitration)"
                          : "clear",
          s_recent_frame_count);

  snprintf(line_reasm, sizeof(line_reasm),
          "Reassembly ctx: active=%u total_frames=%u last_seq=%u last_can_id=0x%03lX",
          s_reassembly.active, s_reassembly.total_frames, s_reassembly.last_seq,
          (unsigned long)s_reassembly.last_can_id);

  size_t width = strlen(title);
  const char *lines[] = {line_motor, line_battery, line_sensor,
                         line_bus,   line_reasm,    line_cmds};
  for (size_t i = 0; i < sizeof(lines) / sizeof(lines[0]); i++) {
    size_t len = strlen(lines[i]);
    if (len > width) {
      width = len;
    }
  }

  scPrintBar(width);
  Serial.println(title);

  Serial.print(s_nodes[0].bus_off ? ANSI_RED : ANSI_CYAN);
  Serial.print(line_motor);
  Serial.println(ANSI_RESET);

  Serial.print(s_nodes[1].bus_off ? ANSI_RED : ANSI_YELLOW);
  Serial.print(line_battery);
  Serial.println(ANSI_RESET);

  Serial.print(s_nodes[2].bus_off ? ANSI_RED : ANSI_MAGENTA);
  Serial.print(line_sensor);
  Serial.println(ANSI_RESET);

  Serial.println();
  Serial.print(s_bus_congested ? ANSI_YELLOW : ANSI_GREEN);
  Serial.print(line_bus);
  Serial.println(ANSI_RESET);
  Serial.println(line_reasm);

  Serial.println();
  Serial.println(line_cmds);
  scPrintBar(width);
}

static void scPrintBanner(void) {
  Serial.print(ANSI_GREEN);
  Serial.println();
  Serial.println("              \\             /");
  Serial.println("               \\           /");
  Serial.println("                +---------+");
  Serial.println("                |         |");
  Serial.println("                | [ ][ ]  |");
  Serial.println("                |         |");
  Serial.println("                +---------+");
  Serial.println("               /           \\");
  Serial.println("              /             \\");
  Serial.println();
  Serial.println("              P W N S A T");
  Serial.println("          --  DEFCON EDITION  --");
  Serial.println(ANSI_RESET);
}

static void scPrintMenu(void) {
  scPrintBanner();
  Serial.println();
  Serial.println("==================================================");
  Serial.println("PWNSAT CONSOLE: Press the number to select.");
  Serial.println("  1) Sensor / Telemetry Dashboard");
  Serial.println("  2) SpaceCAN Bus Console");
  Serial.println("  3) Exit console (quiet mode)");
  Serial.println("Press M anytime to return here.");
  Serial.println("==================================================");
}

/* ---------- Command handling ---------- */

static void scHandleInject(char *args) {
  char *saveptr = NULL;
  char *tok = strtok_r(args, " ", &saveptr);
  if (tok == NULL) {
    Serial.println(
        "[SPACECAN] usage: SC INJECT <can_id_hex> <byte0_hex> [byte1_hex ...]");
    return;
  }

  spacecan_frame_t frame = {0};
  frame.can_id = (uint32_t)strtoul(tok, NULL, 16);

  uint8_t count = 0;
  while ((tok = strtok_r(NULL, " ", &saveptr)) != NULL && count < SC_MAX_DATA_LEN) {
    frame.buffer[count++] = (uint8_t)strtoul(tok, NULL, 16);
  }
  frame.dlc = count;

  Serial.printf("[SPACECAN] INJECT can_id=0x%03lX dlc=%u data=",
                (unsigned long)frame.can_id, frame.dlc);
  for (uint8_t i = 0; i < frame.dlc; i++) {
    Serial.printf("%02X ", frame.buffer[i]);
  }
  Serial.println();

  scTrackFrameRate();

  const bool is_reply_family =
      (frame.can_id & SC_CAN_FUNCTION_MASK) == SC_CANID_REP;
  if (s_bus_congested && is_reply_family) {
    Serial.println(
        "[SPACECAN] frame LOST ARBITRATION (bus congested by higher-priority "
        "request-family traffic) -- dropped");
    scPrintStatus();
    return;
  }

  scDispatchFrame(&frame);

  uint8_t reassembled[SC_MAX_PACKET_SIZE];
  size_t reassembled_len = 0;
  int ret = scReassemblyPackets(&s_reassembly, &frame, millis(), reassembled,
                                &reassembled_len);
  if (ret == 1) {
    Serial.printf("[SPACECAN] packet reassembled, %u bytes:\r\n",
                  (unsigned)reassembled_len);
    for (size_t i = 0; i < reassembled_len; i++) {
      Serial.printf("%02X ", reassembled[i]);
    }
    Serial.println();
  } else if (ret == -1) {
    Serial.println("[SPACECAN] fragment rejected (bad dlc/seq/total)");
  } else {
    Serial.println("[SPACECAN] fragment accepted, waiting for the rest");
  }

  scPrintStatus();
}

static void scHandleReset(char *args) {
  while (*args == ' ') {
    args++;
  }
  uint8_t node_id = (uint8_t)strtoul(args, NULL, 16) & SC_CAN_NODE_MASK;
  sc_node_state_t *node = scFindNode(node_id);
  if (node == NULL) {
    Serial.printf("[SPACECAN] unknown node 0x%02X\r\n", node_id);
    return;
  }
  node->bus_off = false;
  node->error_count = 0;
  Serial.printf("[SPACECAN] node 0x%02X manually reset (bus-off cleared)\r\n",
                node_id);
  scPrintStatus();
}

static void scProcessLine(char *line) {
  while (*line == ' ') {
    line++;
  }
  size_t len = strlen(line);
  while (len > 0 && line[len - 1] == ' ') {
    line[--len] = '\0';
  }
  if (len == 0) {
    Serial.print("SPACECAN> ");
    return;
  }

  if (strcmp(line, "SC STATUS") == 0) {
    scPrintStatus();
  } else if (strncmp(line, "SC INJECT ", 10) == 0) {
    scHandleInject(line + 10);
  } else if (strncmp(line, "SC RESET ", 9) == 0) {
    scHandleReset(line + 9);
  } else {
    Serial.println(
        "[SPACECAN] unknown command (try: SC STATUS, SC INJECT <id> <bytes>, SC RESET <id>, or M for menu)");
  }
  Serial.print("SPACECAN> ");
}

static bool scHandleModeKey(char c) {
  if (c == '1') {
    s_mode = CONSOLE_MODE_SENSORS;
    Serial.println("1");
    Serial.println("[CONSOLE] Sensor / Telemetry Dashboard selected");
    return true;
  }
  if (c == '2') {
    s_mode = CONSOLE_MODE_SPACECAN;
    Serial.println("2");
    Serial.println("[CONSOLE] SpaceCAN Bus Console selected");
    scPrintStatus();
    Serial.print("SPACECAN> ");
    return true;
  }
  if (c == '3') {
    s_mode = CONSOLE_MODE_IDLE;
    Serial.println("3");
    Serial.println();
    Serial.println("[CONSOLE] Exiting console (quiet mode) -- no more automatic output.");
    Serial.println("[CONSOLE] Press M to bring the menu back at any time.");
    Serial.println("[CONSOLE] To actually close this screen session: Ctrl-A then K, then y.");
    return true;
  }
  if (c == 'm' || c == 'M') {
    s_mode = CONSOLE_MODE_MENU;
    Serial.println("M");
    scPrintMenu();
    return true;
  }
  return false;
}

bool consoleSensorModeActive(void) { return s_mode == CONSOLE_MODE_SENSORS; }

bool consoleSpacecanModeActive(void) { return s_mode == CONSOLE_MODE_SPACECAN; }

void consoleWorker(void) {
  if (!s_hint_printed) {
    s_hint_printed = true;
    s_last_status_ms = millis();
    scPrintMenu();
  }

  while (Serial.available() > 0) {
    char c = (char)Serial.read();

    if (s_line_len == 0 && (c == '1' || c == '2' || c == '3' || c == 'm' || c == 'M')) {
      if (scHandleModeKey(c)) {
        continue;
      }
    }

    if (s_mode != CONSOLE_MODE_SPACECAN) {
      continue;
    }
    if (c == '\r' || c == '\n') {
      Serial.println();
      s_line_buf[s_line_len] = '\0';
      scProcessLine(s_line_buf);
      s_line_len = 0;
      continue;
    }
    if (c == 0x7F || c == 0x08) { // backspace/delete
      if (s_line_len > 0) {
        s_line_len--;
        Serial.print("\b \b");
      }
      continue;
    }
    Serial.write((uint8_t)c);
    if (s_line_len + 1 < sizeof(s_line_buf)) {
      s_line_buf[s_line_len++] = c;
    }
  }

  if (s_mode == CONSOLE_MODE_MENU && (millis() - s_last_status_ms > 10000)) {
    s_last_status_ms = millis();
    scPrintMenu();
  }
}
