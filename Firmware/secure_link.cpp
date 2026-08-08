/*  - secure_link.cpp
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#include "secure_link.h"
#include <string.h>

#define SECURE_LINK_AES_BLOCK_SIZE 16
#define SECURE_LINK_AES_ROUNDS 10
#define SECURE_LINK_ROUND_KEY_BYTES 176
#define SECURE_LINK_META_SIZE 2

static bool secure_link_enabled = true;
static bool secure_link_tables_ready = false;
static uint8_t secure_link_sbox[256] = {0};
static uint8_t secure_link_inv_sbox[256] = {0};
static const uint8_t secure_link_rcon[11] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10,
                                             0x20, 0x40, 0x80, 0x1B, 0x36};
static const uint8_t secure_link_key[SECURE_LINK_AES_KEY_SIZE] = {
    'P', 'W', 'N', 's', 'a', 't', 'L', 'a',
    'b', 'K', 'e', 'y', '1', '2', '3', '4',
};

static size_t secureLinkPaddedLen(size_t plain_len) {
  const size_t total_len = plain_len + SECURE_LINK_META_SIZE;
  return (total_len + (SECURE_LINK_AES_BLOCK_SIZE - 1)) &
         ~(SECURE_LINK_AES_BLOCK_SIZE - 1);
}

static uint8_t secureLinkRotateLeft(uint8_t value, uint8_t shift) {
  return (uint8_t)((value << shift) | (value >> (8 - shift)));
}

static uint8_t secureLinkGfMultiply(uint8_t left, uint8_t right) {
  uint8_t result = 0;
  while (right > 0) {
    if ((right & 0x01) != 0) {
      result ^= left;
    }
    const uint8_t hi_bit = left & 0x80;
    left <<= 1;
    if (hi_bit != 0) {
      left ^= 0x1B;
    }
    right >>= 1;
  }
  return result;
}

static uint8_t secureLinkGfPow(uint8_t value, uint8_t exponent) {
  uint8_t result = 0x01;
  while (exponent > 0) {
    if ((exponent & 0x01) != 0) {
      result = secureLinkGfMultiply(result, value);
    }
    value = secureLinkGfMultiply(value, value);
    exponent >>= 1;
  }
  return result;
}

static uint8_t secureLinkGfInverse(uint8_t value) {
  if (value == 0) {
    return 0;
  }
  return secureLinkGfPow(value, 254);
}

static void secureLinkInitTables(void) {
  if (secure_link_tables_ready) {
    return;
  }

  for (uint16_t i = 0; i < 256; i++) {
    const uint8_t inv = secureLinkGfInverse((uint8_t)i);
    const uint8_t sbox =
        (uint8_t)(0x63 ^ inv ^ secureLinkRotateLeft(inv, 1) ^
                  secureLinkRotateLeft(inv, 2) ^ secureLinkRotateLeft(inv, 3) ^
                  secureLinkRotateLeft(inv, 4));
    secure_link_sbox[i] = sbox;
    secure_link_inv_sbox[sbox] = (uint8_t)i;
  }

  secure_link_tables_ready = true;
}

static void secureLinkKeyExpansion(uint8_t round_keys[SECURE_LINK_ROUND_KEY_BYTES]) {
  secureLinkInitTables();
  memcpy(round_keys, secure_link_key, SECURE_LINK_AES_KEY_SIZE);

  uint8_t temp[4] = {0};
  size_t bytes_generated = SECURE_LINK_AES_KEY_SIZE;
  uint8_t rcon_index = 1;

  while (bytes_generated < SECURE_LINK_ROUND_KEY_BYTES) {
    for (uint8_t i = 0; i < 4; i++) {
      temp[i] = round_keys[bytes_generated - 4 + i];
    }

    if ((bytes_generated % SECURE_LINK_AES_KEY_SIZE) == 0) {
      const uint8_t first = temp[0];
      temp[0] = secure_link_sbox[temp[1]] ^ secure_link_rcon[rcon_index++];
      temp[1] = secure_link_sbox[temp[2]];
      temp[2] = secure_link_sbox[temp[3]];
      temp[3] = secure_link_sbox[first];
    }

    for (uint8_t i = 0; i < 4; i++) {
      round_keys[bytes_generated] =
          round_keys[bytes_generated - SECURE_LINK_AES_KEY_SIZE] ^ temp[i];
      bytes_generated++;
    }
  }
}

static void secureLinkAddRoundKey(uint8_t state[SECURE_LINK_AES_BLOCK_SIZE],
                                  const uint8_t *round_key) {
  for (uint8_t i = 0; i < SECURE_LINK_AES_BLOCK_SIZE; i++) {
    state[i] ^= round_key[i];
  }
}

static void secureLinkSubBytes(uint8_t state[SECURE_LINK_AES_BLOCK_SIZE]) {
  for (uint8_t i = 0; i < SECURE_LINK_AES_BLOCK_SIZE; i++) {
    state[i] = secure_link_sbox[state[i]];
  }
}

static void secureLinkInvSubBytes(uint8_t state[SECURE_LINK_AES_BLOCK_SIZE]) {
  for (uint8_t i = 0; i < SECURE_LINK_AES_BLOCK_SIZE; i++) {
    state[i] = secure_link_inv_sbox[state[i]];
  }
}

static void secureLinkShiftRows(uint8_t state[SECURE_LINK_AES_BLOCK_SIZE]) {
  uint8_t temp = state[1];
  state[1] = state[5];
  state[5] = state[9];
  state[9] = state[13];
  state[13] = temp;

  temp = state[2];
  uint8_t temp2 = state[6];
  state[2] = state[10];
  state[6] = state[14];
  state[10] = temp;
  state[14] = temp2;

  temp = state[15];
  state[15] = state[11];
  state[11] = state[7];
  state[7] = state[3];
  state[3] = temp;
}

static void secureLinkInvShiftRows(uint8_t state[SECURE_LINK_AES_BLOCK_SIZE]) {
  uint8_t temp = state[13];
  state[13] = state[9];
  state[9] = state[5];
  state[5] = state[1];
  state[1] = temp;

  temp = state[2];
  uint8_t temp2 = state[6];
  state[2] = state[10];
  state[6] = state[14];
  state[10] = temp;
  state[14] = temp2;

  temp = state[3];
  state[3] = state[7];
  state[7] = state[11];
  state[11] = state[15];
  state[15] = temp;
}

static void secureLinkMixColumns(uint8_t state[SECURE_LINK_AES_BLOCK_SIZE]) {
  for (uint8_t col = 0; col < 4; col++) {
    const uint8_t offset = col * 4;
    const uint8_t s0 = state[offset];
    const uint8_t s1 = state[offset + 1];
    const uint8_t s2 = state[offset + 2];
    const uint8_t s3 = state[offset + 3];

    state[offset] = secureLinkGfMultiply(s0, 0x02) ^
                    secureLinkGfMultiply(s1, 0x03) ^ s2 ^ s3;
    state[offset + 1] = s0 ^ secureLinkGfMultiply(s1, 0x02) ^
                        secureLinkGfMultiply(s2, 0x03) ^ s3;
    state[offset + 2] = s0 ^ s1 ^ secureLinkGfMultiply(s2, 0x02) ^
                        secureLinkGfMultiply(s3, 0x03);
    state[offset + 3] = secureLinkGfMultiply(s0, 0x03) ^ s1 ^ s2 ^
                        secureLinkGfMultiply(s3, 0x02);
  }
}

static void secureLinkInvMixColumns(uint8_t state[SECURE_LINK_AES_BLOCK_SIZE]) {
  for (uint8_t col = 0; col < 4; col++) {
    const uint8_t offset = col * 4;
    const uint8_t s0 = state[offset];
    const uint8_t s1 = state[offset + 1];
    const uint8_t s2 = state[offset + 2];
    const uint8_t s3 = state[offset + 3];

    state[offset] = secureLinkGfMultiply(s0, 0x0E) ^
                    secureLinkGfMultiply(s1, 0x0B) ^
                    secureLinkGfMultiply(s2, 0x0D) ^
                    secureLinkGfMultiply(s3, 0x09);
    state[offset + 1] = secureLinkGfMultiply(s0, 0x09) ^
                        secureLinkGfMultiply(s1, 0x0E) ^
                        secureLinkGfMultiply(s2, 0x0B) ^
                        secureLinkGfMultiply(s3, 0x0D);
    state[offset + 2] = secureLinkGfMultiply(s0, 0x0D) ^
                        secureLinkGfMultiply(s1, 0x09) ^
                        secureLinkGfMultiply(s2, 0x0E) ^
                        secureLinkGfMultiply(s3, 0x0B);
    state[offset + 3] = secureLinkGfMultiply(s0, 0x0B) ^
                        secureLinkGfMultiply(s1, 0x0D) ^
                        secureLinkGfMultiply(s2, 0x09) ^
                        secureLinkGfMultiply(s3, 0x0E);
  }
}

static void secureLinkEncryptBlock(
    uint8_t state[SECURE_LINK_AES_BLOCK_SIZE],
    const uint8_t round_keys[SECURE_LINK_ROUND_KEY_BYTES]) {
  secureLinkAddRoundKey(state, round_keys);

  for (uint8_t round = 1; round < SECURE_LINK_AES_ROUNDS; round++) {
    secureLinkSubBytes(state);
    secureLinkShiftRows(state);
    secureLinkMixColumns(state);
    secureLinkAddRoundKey(state, round_keys + (round * SECURE_LINK_AES_BLOCK_SIZE));
  }

  secureLinkSubBytes(state);
  secureLinkShiftRows(state);
  secureLinkAddRoundKey(
      state, round_keys + (SECURE_LINK_AES_ROUNDS * SECURE_LINK_AES_BLOCK_SIZE));
}

static void secureLinkDecryptBlock(
    uint8_t state[SECURE_LINK_AES_BLOCK_SIZE],
    const uint8_t round_keys[SECURE_LINK_ROUND_KEY_BYTES]) {
  secureLinkAddRoundKey(
      state, round_keys + (SECURE_LINK_AES_ROUNDS * SECURE_LINK_AES_BLOCK_SIZE));

  for (int round = SECURE_LINK_AES_ROUNDS - 1; round > 0; round--) {
    secureLinkInvShiftRows(state);
    secureLinkInvSubBytes(state);
    secureLinkAddRoundKey(state,
                          round_keys + (round * SECURE_LINK_AES_BLOCK_SIZE));
    secureLinkInvMixColumns(state);
  }

  secureLinkInvShiftRows(state);
  secureLinkInvSubBytes(state);
  secureLinkAddRoundKey(state, round_keys);
}

bool secureLinkIsEnabled(void) { return secure_link_enabled; }

void secureLinkSetEnabled(bool enabled) { secure_link_enabled = enabled; }

const uint8_t *secureLinkKeyBytes(void) { return secure_link_key; }

size_t secureLinkKeySize(void) { return sizeof(secure_link_key); }

bool secureLinkEncodePayload(const uint8_t *input, uint16_t input_len,
                             uint8_t *output, uint16_t *output_len) {
  if (output == NULL || output_len == NULL) {
    return false;
  }

  const size_t padded_len = secureLinkPaddedLen(input_len);
  if (padded_len > SPP_MAX_PAYLOAD_CHUNK) {
    return false;
  }
  if (input_len > 0 && input == NULL) {
    return false;
  }

  uint8_t round_keys[SECURE_LINK_ROUND_KEY_BYTES] = {0};
  uint8_t plain_buffer[SPP_MAX_PAYLOAD_CHUNK] = {0};
  secureLinkKeyExpansion(round_keys);

  plain_buffer[0] = (uint8_t)((input_len >> 8) & 0xFF);
  plain_buffer[1] = (uint8_t)(input_len & 0xFF);
  if (input_len > 0) {
    memcpy(plain_buffer + SECURE_LINK_META_SIZE, input, input_len);
  }

  for (size_t offset = 0; offset < padded_len; offset += SECURE_LINK_AES_BLOCK_SIZE) {
    memcpy(output + offset, plain_buffer + offset, SECURE_LINK_AES_BLOCK_SIZE);
    secureLinkEncryptBlock(output + offset, round_keys);
  }

  *output_len = (uint16_t)padded_len;
  return true;
}

bool secureLinkDecodePayload(const uint8_t *input, uint16_t input_len,
                             uint8_t *output, uint16_t *output_len) {
  if (input == NULL || output == NULL || output_len == NULL) {
    return false;
  }
  if (input_len == 0 || (input_len % SECURE_LINK_AES_BLOCK_SIZE) != 0) {
    return false;
  }
  if (input_len > SPP_MAX_PAYLOAD_CHUNK) {
    return false;
  }

  uint8_t round_keys[SECURE_LINK_ROUND_KEY_BYTES] = {0};
  uint8_t plain_buffer[SPP_MAX_PAYLOAD_CHUNK] = {0};
  secureLinkKeyExpansion(round_keys);

  for (size_t offset = 0; offset < input_len; offset += SECURE_LINK_AES_BLOCK_SIZE) {
    memcpy(plain_buffer + offset, input + offset, SECURE_LINK_AES_BLOCK_SIZE);
    secureLinkDecryptBlock(plain_buffer + offset, round_keys);
  }

  const uint16_t plain_len =
      ((uint16_t)plain_buffer[0] << 8) | (uint16_t)plain_buffer[1];
  if (plain_len > (uint16_t)(input_len - SECURE_LINK_META_SIZE)) {
    return false;
  }
  if (plain_len > SPP_MAX_PAYLOAD_CHUNK) {
    return false;
  }

  if (plain_len > 0) {
    memcpy(output, plain_buffer + SECURE_LINK_META_SIZE, plain_len);
  }
  *output_len = plain_len;
  return true;
}
