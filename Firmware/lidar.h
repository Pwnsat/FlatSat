/*  - lidar.h
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#ifndef FIRMWARE_LIDAR_H
#define FIRMWARE_LIDAR_H
#include <Arduino.h>

/* Tau LiDAR Camera payload (Onion / ESPROS epc660, 160x60, millimetres).
 *
 * The camera is a USB-CDC device driven by a companion payload-host processor
 * (Raspberry Pi / laptop running Payloads/lidar/tau_lidar_bridge.py). The host
 * reduces each depth frame to the summary below and uplinks it to the OBC as
 * SPP_APID_TC_SET_LIDAR_FRAME. The OBC stores it and re-downlinks it as
 * SPP_APID_TM_LIDAR -- the classic "smart payload + store-and-forward OBC"
 * architecture the FlatSat firmware already models (payloadForwardCount).
 */

#define LIDAR_FRAME_WIDTH 160
#define LIDAR_FRAME_HEIGHT 60
#define LIDAR_DIST_INVALID 0xFFFF /* no-return / out-of-window sentinel (mm) */

/* status bits (lidar_summary_t.status) */
#define LIDAR_STATUS_FRAME_VALID 0x01 /* frame had at least one valid return  */
#define LIDAR_STATUS_ALL_INVALID 0x02 /* whole frame was no-return / masked   */
#define LIDAR_STATUS_SATURATED 0x04   /* majority of pixels at/over max range  */

/* Reduced depth-frame summary forwarded by the payload host. Little-endian on
 * the wire; see lidarIngestSummary() for the exact byte layout. */
typedef struct {
  uint8_t frameType;   /* TauLidar FrameType: 0 DIST, 1 +GRAY, 2 +AMPL */
  uint16_t minMm;      /* nearest valid return                         */
  uint16_t maxMm;      /* farthest valid return                        */
  uint16_t meanMm;     /* mean of valid returns                        */
  uint16_t centerMm;   /* center-pixel distance                        */
  uint8_t validPct;    /* percentage of valid pixels (0..100)          */
  uint16_t amplitude;  /* mean return amplitude / confidence           */
  uint16_t width;      /* frame columns (160)                          */
  uint16_t height;     /* frame rows (60)                              */
  uint32_t frameCount; /* host-side monotonic frame counter            */
  uint8_t status;      /* LIDAR_STATUS_* bits                          */
} lidar_summary_t;

/* Wire length of the summary block (excludes the leading SPACECRAFT_ID byte). */
#define LIDAR_SUMMARY_WIRE_LEN 21

void lidarConfigure(void);
/* Parse a host-uplinked summary block (the TC data field *after* the leading
 * SPACECRAFT_ID byte). Returns true and stores it on success. */
bool lidarIngestSummary(const uint8_t *data, uint16_t len);
bool lidarRead(lidar_summary_t *out); /* copy last stored summary */
bool lidarHasFix(void);               /* have a summary with a valid frame */
uint16_t lidarIngestCount(void);
uint16_t lidarSecondsSinceLast(void); /* 0xFFFF if never */

#endif // FIRMWARE_LIDAR_H
