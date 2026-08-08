/*  - spp.h
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#ifndef FIRMWARE_SPP_H
#define FIRMWARE_SPP_H
#include <Arduino.h>
#include <stdint.h>
#include <string.h>

#define CCSDS_SPP_VERSION 0 // 4.1.3.2.2 133B2 SPP CCSDS
#define SPP_APID_IDLE 0b1111111111
#define SPP_MAX_PAYLOAD_CHUNK 200
#define SPP_PRIMARY_HEADER_LEN (6)
// Secondary header content: a 4-byte monotonic session/command counter,
// nothing cryptographic. No IV, no timestamp, no freshness validation --
// this is the plain CCSDS structure only, opt-in per packet via the
// SecHdr flag, parallel to (never replacing) the existing no-sec-header
// path every other APID still uses.
#define SPP_SECONDARY_HEADER_LEN (4)

#define HOST_TO_BE16(n)                                                        \
  (uint16_t)((((uint16_t)(n) & 0xFF00) >> 8) | (((uint16_t)(n) & 0x00FF) << 8))
#define BE_TO_HOST16(n)                                                        \
  (uint16_t)((((uint16_t)(n) & 0xFF00) >> 8) | (((uint16_t)(n) & 0x00FF) << 8))

enum {
  SPP_ERROR_NONE = 0,
  SPP_ERROR_PAYLOAD_LEN = -1,
  SPP_ERROR_PACKET_LEN = -2,
  SPP_ERROR_PAYLOAD_LEN_OUT_LIMITS = -3,
  SPP_ERROR_VERSION = -4,
  SPP_ERROR_MALFORMED_SEC_HEADER = -5,
  SPP_ERROR_INVALID_BUFFER = -6,
  SPP_ERROR_INVALID_APID = -7
};

enum {
  /** @brief Telemetry or Reporting */
  SPP_PTYPE_TM = 0x00,
  /** @brief Telecommand or Requesting */
  SPP_PTYPE_TC = 0x01,
};

enum {
  /** @brief Secondary Header Flag no present. IDLE Packe will use this.*/
  SPP_SECHEAD_FLAG_NOPRESENT = 0x00,
  /** @brief Secondary Header Flag Present */
  SPP_SECHEAD_FLAG_PRESENT = 0x01
};

enum {
  /** @brief Continuation segment of User Data */
  SPP_GROUP_FLAG_CONT = 0b00,
  /** @brief First segment of User Data */
  SPP_GROUP_FLAG_START = 0b01,
  /** @brief Last segment User Data */
  SPP_GROUP_FLAG_END = 0b10,
  /** @brief Unsegmented User Data */
  SPP_GROUP_FLAG_UNSEGMENTED = 0b11
};

/** @brief Primary Header 6 bytes
 * Packet Version | Packet Identification | Packet Sequence | Packet Data Length
 *      3 bits    |         13 bits       |      16 bits    |       16 bits
 *                  2 octets              |      2 octets   |       2 octets
 */
typedef struct {
  uint16_t identification; // Version(3) + Type(1) + SecHdr(1) + APID(11)
  uint16_t sequence;       // Seq flags(2) + Seq count(14)
  uint16_t length; // Packet length = (len(payload) + len(secondary_header)) - 1
} __attribute__((packed)) sp_primary_header_t;

typedef struct {
  sp_primary_header_t header;
  uint8_t data[SPP_MAX_PAYLOAD_CHUNK]; // Secondary header + payload
} __attribute__((packed)) space_packet_t;

int spp_tc_build_packet(space_packet_t *space_packet, uint8_t flag,
                        uint8_t sec_header, uint16_t sec_header_len,
                        uint16_t apid, const uint8_t *data, uint16_t data_len);
int spp_tm_build_packet(space_packet_t *space_packet, uint8_t flag,
                        uint8_t sec_header, uint16_t sec_header_len,
                        uint16_t apid, const uint8_t *data, uint16_t data_len);
int spp_idle_build_packet(space_packet_t *space_packet);
int spp_unpack_packet(space_packet_t *space_packet, const uint8_t *buffer,
                      uint16_t buffer_len);

// Secured-format builders: prepend a SPP_SECONDARY_HEADER_LEN-byte counter
// (big-endian) between the primary header and the payload, and set the
// SecHdr flag accordingly. This is an additional packet format alongside
// spp_tc/tm_build_packet above; callers choose which one to use per APID.
int spp_tc_build_packet_secured(space_packet_t *space_packet, uint8_t flag,
                                uint16_t apid, uint32_t sechdr_counter,
                                const uint8_t *data, uint16_t data_len);
int spp_tm_build_packet_secured(space_packet_t *space_packet, uint8_t flag,
                                uint16_t apid, uint32_t sechdr_counter,
                                const uint8_t *data, uint16_t data_len);

#endif // FIRMWARE_SPP_H