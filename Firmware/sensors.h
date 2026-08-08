/*  - sensors.h
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#ifndef FIRMWARE_SENSORS_H
#define FIRMWARE_SENSORS_H
#include <Arduino.h>

#define SEALEVELPRESSURE_HPA (1013.25)
#define BME_ADDR 0x76

typedef struct {
  bool uartOk;
  bool connected;
  bool nmeaActive;
  bool hasFix;
  bool hasDateTime;
  int32_t latitudeE7;
  int32_t longitudeE7;
  int32_t altitudeCm;
  uint8_t satellites;
  uint8_t utcHour;
  uint8_t utcMinute;
  uint8_t utcSecond;
  uint8_t utcDay;
  uint8_t utcMonth;
  uint16_t utcYear;
  unsigned long lastByteMs;
  unsigned long lastNmeaMs;
  unsigned long lastDateTimeMs;
  unsigned long lastFixMs;
} gps_nav_t;

void sensorsConfigure(void);
bool accelerometerRead(float *x, float *y, float *z, float *temp);
bool bmeRead(float *t, float *p, float *alt, float *hum);
void gpsPoll(void);
bool gpsRead(gps_nav_t *nav);
uint8_t gpsStatusByte(const gps_nav_t *nav);
uint8_t sensorsStatusFlags(void);
#endif // FIRMWARE_SENSORS_H
