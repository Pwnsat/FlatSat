/*  - led.ino
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#include "led.h"
#include "pins.h"
#include <NeoPixelBus.h>

NeoPixelBus<NeoGrbFeature, NeoWs2812xMethod> strip(LED_PIXEL_COUNT,
                                                   PIN_RGB_LED);

RgbColor ledColor_red(colorSaturation, 0, 0);
RgbColor ledColor_green(0, colorSaturation, 0);
RgbColor ledColor_blue(0, 0, colorSaturation);
RgbColor ledColor_yellow(colorSaturation, colorSaturation, 0);
RgbColor ledColor_white(colorSaturation);
RgbColor ledColor_black(0);

void ledConfigure(void) { strip.Begin(); }

void ledTurnRed(void) {
  strip.SetPixelColor(0, ledColor_red);
  strip.Show();
}

void ledTurnGreen(void) {
  strip.SetPixelColor(0, ledColor_green);
  strip.Show();
}

void ledTurnBlue(void) {
  strip.SetPixelColor(0, ledColor_blue);
  strip.Show();
}

void ledTurnWhite(void) {
  strip.SetPixelColor(0, ledColor_white);
  strip.Show();
}

void ledTurnOff(void) {
  strip.SetPixelColor(0, ledColor_black);
  strip.Show();
}

RgbColor ledColorSelector(led_color_t color) {
  switch (color) {
  case LED_COLOR_RED:
    return ledColor_red;
    break;
  case LED_COLOR_GREEN:
    return ledColor_green;
    break;
  case LED_COLOR_BLUE:
    return ledColor_blue;
    break;
  case LED_COLOR_WHITE:
    return ledColor_white;
    break;
  case LED_COLOR_YELLOW:
    return ledColor_yellow;
    break;
  default:
    return ledColor_red;
    break;
  }
}

void ledBlink(uint8_t count, led_color_t color) {
  for (int i = 0; i < count; i++) {
    strip.SetPixelColor(0, ledColorSelector(color));
    strip.Show();
    delay(200);
    ledTurnOff();
    delay(200);
  }
}