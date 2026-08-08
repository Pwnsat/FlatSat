/*  - spp.cpp
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#include "spp.h"

typedef struct {
  uint16_t tc;
  uint16_t tm;
} packet_counter_t;

static packet_counter_t packet_counter = {.tc = 0, .tm = 0};

static void spp_validate_counters() {
  if (packet_counter.tc == 16383) {
    packet_counter.tc = 0;
  }
  if (packet_counter.tm == 16383) {
    packet_counter.tm = 0;
  }
}

static int spp_build_packet(space_packet_t *space_packet, uint8_t type,
                            uint8_t flag, uint8_t sec_header,
                            uint16_t sec_header_len, uint16_t apid,
                            uint16_t sequence_count, const uint8_t *data,
                            uint16_t data_len) {

  uint16_t packet_id = 0;
  packet_id |= (CCSDS_SPP_VERSION & 0x07) << 13;
  packet_id |= (type & 0x01) << 12;
  packet_id |= (sec_header & 0x01) << 11;
  packet_id |= (apid & 0x07FF);

  uint16_t seq_ctrl = 0;
  seq_ctrl |= (flag & 0x03) << 14;
  seq_ctrl |= (sequence_count & 0x3FFF);

  space_packet->header.identification = HOST_TO_BE16(packet_id);
  space_packet->header.sequence = HOST_TO_BE16(seq_ctrl);
  space_packet->header.length = HOST_TO_BE16(data_len + sec_header_len - 1);

  if (data_len > 0 && data != NULL) {
    memcpy(space_packet->data, data, data_len);
  }

  return SPP_ERROR_NONE;
}

int spp_tc_build_packet(space_packet_t *space_packet, uint8_t flag,
                        uint8_t sec_header, uint16_t sec_header_len,
                        uint16_t apid, const uint8_t *data, uint16_t data_len) {
  spp_validate_counters();
  packet_counter.tc++;
  return spp_build_packet(space_packet, SPP_PTYPE_TC, flag, sec_header,
                          sec_header_len, apid, packet_counter.tc, data,
                          data_len);
}

int spp_tm_build_packet(space_packet_t *space_packet, uint8_t flag,
                        uint8_t sec_header, uint16_t sec_header_len,
                        uint16_t apid, const uint8_t *data, uint16_t data_len) {
  spp_validate_counters();
  packet_counter.tm++;
  return spp_build_packet(space_packet, SPP_PTYPE_TM, flag, sec_header,
                          sec_header_len, apid, packet_counter.tm, data,
                          data_len);
}

// ---------------------------------------------------------------------
// Secured-format path: prepends a fixed-length secondary header (a plain
// counter, no crypto) between the primary header and the payload, and
// sets the SecHdr flag. Used alongside spp_build_packet() above, which
// builds the default (no secondary header) packet format.
// ---------------------------------------------------------------------
static int spp_build_packet_with_sechdr(space_packet_t *space_packet,
                                        uint8_t type, uint8_t flag,
                                        uint16_t apid, uint16_t sequence_count,
                                        const uint8_t *sec_header_data,
                                        uint16_t sec_header_len,
                                        const uint8_t *data, uint16_t data_len) {
  if ((uint32_t)sec_header_len + (uint32_t)data_len > SPP_MAX_PAYLOAD_CHUNK) {
    return SPP_ERROR_PAYLOAD_LEN_OUT_LIMITS;
  }

  uint16_t packet_id = 0;
  packet_id |= (CCSDS_SPP_VERSION & 0x07) << 13;
  packet_id |= (type & 0x01) << 12;
  packet_id |= (SPP_SECHEAD_FLAG_PRESENT & 0x01) << 11;
  packet_id |= (apid & 0x07FF);

  uint16_t seq_ctrl = 0;
  seq_ctrl |= (flag & 0x03) << 14;
  seq_ctrl |= (sequence_count & 0x3FFF);

  space_packet->header.identification = HOST_TO_BE16(packet_id);
  space_packet->header.sequence = HOST_TO_BE16(seq_ctrl);
  space_packet->header.length = HOST_TO_BE16(sec_header_len + data_len - 1);

  memcpy(space_packet->data, sec_header_data, sec_header_len);
  if (data_len > 0 && data != NULL) {
    memcpy(space_packet->data + sec_header_len, data, data_len);
  }

  return SPP_ERROR_NONE;
}

static void spp_pack_sechdr_counter(uint8_t *out, uint32_t counter) {
  out[0] = (uint8_t)(counter >> 24);
  out[1] = (uint8_t)(counter >> 16);
  out[2] = (uint8_t)(counter >> 8);
  out[3] = (uint8_t)(counter);
}

int spp_tc_build_packet_secured(space_packet_t *space_packet, uint8_t flag,
                                uint16_t apid, uint32_t sechdr_counter,
                                const uint8_t *data, uint16_t data_len) {
  spp_validate_counters();
  packet_counter.tc++;
  uint8_t sechdr[SPP_SECONDARY_HEADER_LEN];
  spp_pack_sechdr_counter(sechdr, sechdr_counter);
  return spp_build_packet_with_sechdr(space_packet, SPP_PTYPE_TC, flag, apid,
                                      packet_counter.tc, sechdr,
                                      SPP_SECONDARY_HEADER_LEN, data, data_len);
}

int spp_tm_build_packet_secured(space_packet_t *space_packet, uint8_t flag,
                                uint16_t apid, uint32_t sechdr_counter,
                                const uint8_t *data, uint16_t data_len) {
  spp_validate_counters();
  packet_counter.tm++;
  uint8_t sechdr[SPP_SECONDARY_HEADER_LEN];
  spp_pack_sechdr_counter(sechdr, sechdr_counter);
  return spp_build_packet_with_sechdr(space_packet, SPP_PTYPE_TM, flag, apid,
                                      packet_counter.tm, sechdr,
                                      SPP_SECONDARY_HEADER_LEN, data, data_len);
}

int spp_idle_build_packet(space_packet_t *space_packet) {
  const uint16_t buffer_len = 14;
  const uint8_t buffer_idle[buffer_len] = {0x48, 0x61, 0x63, 0x6b, 0x54,
                                           0x68, 0x65, 0x57, 0x6f, 0x72,
                                           0x6c, 0x64, 0x21, 0x00};
  return spp_build_packet(
      space_packet, SPP_PTYPE_TM, SPP_GROUP_FLAG_UNSEGMENTED,
      SPP_SECHEAD_FLAG_NOPRESENT, 0, SPP_APID_IDLE, 0, buffer_idle, buffer_len);
}

int spp_unpack_packet(space_packet_t *space_packet, const uint8_t *buffer,
                      uint16_t buffer_len) {
  if (buffer_len < SPP_PRIMARY_HEADER_LEN) {
    return SPP_ERROR_PACKET_LEN;
  }
  if (buffer == NULL) {
    return SPP_ERROR_INVALID_BUFFER;
  }

  memset(space_packet, 0, sizeof(space_packet_t));
  space_packet->header.identification = ((uint16_t)buffer[0] << 8) | buffer[1];
  space_packet->header.sequence = ((uint16_t)buffer[2] << 8) | buffer[3];
  space_packet->header.length = ((uint16_t)buffer[4] << 8) | buffer[5];

  uint8_t version = (space_packet->header.identification >> 13) & 0x07;
  if (version != CCSDS_SPP_VERSION) {
    return SPP_ERROR_VERSION;
  }

  if (space_packet->header.length > SPP_MAX_PAYLOAD_CHUNK) {
    return SPP_ERROR_PAYLOAD_LEN;
  }

  if (space_packet->header.length > 0 && buffer != NULL) {
    memcpy(space_packet->data, buffer + SPP_PRIMARY_HEADER_LEN,
           space_packet->header.length + 1);
  }
  return SPP_ERROR_NONE;
}