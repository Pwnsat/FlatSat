/*  - led.h
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#ifndef FIRMWARE_LED_H
#define FIRMWARE_LED_H
#include <Arduino.h>

#define colorSaturation 60
#define LED_PIXEL_COUNT (1)

typedef enum {
  LED_COLOR_RED,
  LED_COLOR_GREEN,
  LED_COLOR_BLUE,
  LED_COLOR_WHITE,
  LED_COLOR_YELLOW
} led_color_t;

void ledConfigure(void);
void ledTurnRed(void);
void ledTurnGreen(void);
void ledTurnBlue(void);
void ledTurnWhite(void);
void ledTurnOff(void);
void ledBlink(uint8_t count, led_color_t color);

#endif // FIRMWARE_LED_H