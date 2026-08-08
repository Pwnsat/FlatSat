/*  - sensors.cpp
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#include "sensors.h"
#include "SparkFun_LIS2DH12.h"
#include "mission.h"
#include "pins.h"
#include <Adafruit_BME280.h>
#include <Adafruit_Sensor.h>
#include <Wire.h>
#include <string.h>

Adafruit_BME280 bme;
SPARKFUN_LIS2DH12 accel;

#define GPS_BAUD_RATE 9600
#define GPS_LINE_BUFFER_SIZE 128
#define GPS_DETECT_TIMEOUT_MS 3000
#define GPS_NMEA_TIMEOUT_MS 4000
#define GPS_FIX_TIMEOUT_MS 5000

typedef struct {
  bool bmeOk;
  bool accOk;
  gps_nav_t gps;
  char gpsLine[GPS_LINE_BUFFER_SIZE];
  size_t gpsLineLen;
  bool gpsNmeaLogged;
  bool gpsMissingLogged;
} sensor_context_t;

static sensor_context_t s_context;

static void gpsClearFix(void) {
  s_context.gps.hasFix = false;
  s_context.gps.latitudeE7 = 0;
  s_context.gps.longitudeE7 = 0;
  s_context.gps.altitudeCm = 0;
  s_context.gps.satellites = 0;
  s_context.gps.lastFixMs = 0;
}

static void gpsClearDateTime(void) {
  s_context.gps.hasDateTime = false;
  s_context.gps.utcHour = 0;
  s_context.gps.utcMinute = 0;
  s_context.gps.utcSecond = 0;
  s_context.gps.utcDay = 0;
  s_context.gps.utcMonth = 0;
  s_context.gps.utcYear = 0;
  s_context.gps.lastDateTimeMs = 0;
}

static void sensorsInitAcc(void) {
  if (!accel.begin()) {
    Serial.print("[ERROR] ACC_NOT_DETECTED\r\n");
    s_context.accOk = false;
    return;
  }
  Serial.print("[INFO] ACC OK\r\n");
}

static void sensorsInitBme(void) {
  if (!bme.begin(BME_ADDR)) {
    Serial.printf("[ERROR] BMP_NOT_DETECTED. ID: 0x%02X \r\n", bme.sensorID());
    s_context.bmeOk = false;
    return;
  }
  Serial.print("[INFO] BME OK\r\n");
}

static bool gpsParseTwoDigits(const char *value, uint8_t *parsed) {
  if (value == NULL || parsed == NULL || value[0] == '\0' || value[1] == '\0') {
    return false;
  }
  if (value[0] < '0' || value[0] > '9' || value[1] < '0' || value[1] > '9') {
    return false;
  }

  *parsed = (uint8_t)(((value[0] - '0') * 10) + (value[1] - '0'));
  return true;
}

static bool gpsParseScaledDegrees(const char *value, char hemisphere,
                                  int32_t *scaled) {
  if (value == NULL || scaled == NULL || value[0] == '\0') {
    return false;
  }

  const double raw = atof(value);
  const int32_t degrees = (int32_t)(raw / 100.0);
  const double minutes = raw - ((double)degrees * 100.0);
  double decimal = (double)degrees + (minutes / 60.0);

  if (hemisphere == 'S' || hemisphere == 'W') {
    decimal *= -1.0;
  }

  *scaled = (int32_t)(decimal * 10000000.0);
  return true;
}

static bool gpsParseUtcTime(const char *value, uint8_t *hour, uint8_t *minute,
                            uint8_t *second) {
  if (value == NULL || hour == NULL || minute == NULL || second == NULL ||
      strlen(value) < 6) {
    return false;
  }

  return gpsParseTwoDigits(&value[0], hour) &&
         gpsParseTwoDigits(&value[2], minute) &&
         gpsParseTwoDigits(&value[4], second);
}

static bool gpsParseUtcDate(const char *value, uint8_t *day, uint8_t *month,
                            uint16_t *year) {
  uint8_t year_short = 0;

  if (value == NULL || day == NULL || month == NULL || year == NULL ||
      strlen(value) < 6) {
    return false;
  }

  if (!gpsParseTwoDigits(&value[0], day) ||
      !gpsParseTwoDigits(&value[2], month) ||
      !gpsParseTwoDigits(&value[4], &year_short)) {
    return false;
  }

  *year = (uint16_t)(2000 + year_short);
  return true;
}

static size_t gpsSplitLine(char *line, char **fields, size_t max_fields) {
  size_t field_count = 0;
  char *saveptr = NULL;

  for (char *token = strtok_r(line, ",", &saveptr);
       token != NULL && field_count < max_fields;
       token = strtok_r(NULL, ",", &saveptr)) {
    char *checksum = strchr(token, '*');
    if (checksum != NULL) {
      *checksum = '\0';
    }
    fields[field_count++] = token;
  }

  return field_count;
}

static void gpsRefreshAvailability(void) {
  const unsigned long now = millis();

  const bool raw_connected =
      s_context.gps.lastByteMs != 0 &&
      (now - s_context.gps.lastByteMs) <= GPS_NMEA_TIMEOUT_MS;
  const bool nmea_active =
      s_context.gps.lastNmeaMs != 0 &&
      (now - s_context.gps.lastNmeaMs) <= GPS_NMEA_TIMEOUT_MS;

  s_context.gps.connected = raw_connected;
  s_context.gps.nmeaActive = nmea_active;

  if (nmea_active) {
    if (!s_context.gpsNmeaLogged) {
      Serial.println("[INFO] GPS detected, valid NMEA stream active");
      s_context.gpsNmeaLogged = true;
      s_context.gpsMissingLogged = false;
    }
    return;
  }

  if (!raw_connected && now > GPS_DETECT_TIMEOUT_MS && !s_context.gpsMissingLogged) {
    Serial.println("[WARN] GPS not detected on UART, using zero-coordinate fallback");
    s_context.gpsMissingLogged = true;
    s_context.gpsNmeaLogged = false;
  } else if (raw_connected && s_context.gps.lastNmeaMs != 0 &&
             !s_context.gpsMissingLogged) {
    Serial.println("[WARN] GPS NMEA stream timed out, using zero-coordinate fallback");
    s_context.gpsMissingLogged = true;
    s_context.gpsNmeaLogged = false;
  }
}

static void gpsRegisterNmeaSentence(void) {
  s_context.gps.lastNmeaMs = millis();
  s_context.gps.nmeaActive = true;
}

static void gpsApplyGga(char *line) {
  char *fields[16] = {0};
  const size_t field_count = gpsSplitLine(line, fields, 16);

  if (field_count < 10) {
    return;
  }

  gpsRegisterNmeaSentence();

  const int fix_quality = atoi(fields[6]);
  const uint8_t satellites = (uint8_t)atoi(fields[7]);
  const unsigned long now = millis();

  if (fix_quality <= 0) {
    gpsClearFix();
    return;
  }

  int32_t latitude_e7 = 0;
  int32_t longitude_e7 = 0;
  if (!gpsParseScaledDegrees(fields[2], fields[3][0], &latitude_e7) ||
      !gpsParseScaledDegrees(fields[4], fields[5][0], &longitude_e7)) {
    gpsClearFix();
    return;
  }

  s_context.gps.hasFix = true;
  s_context.gps.latitudeE7 = latitude_e7;
  s_context.gps.longitudeE7 = longitude_e7;
  s_context.gps.altitudeCm = (int32_t)(atof(fields[9]) * 100.0);
  s_context.gps.satellites = satellites;
  s_context.gps.lastFixMs = now;
}

static void gpsApplyRmc(char *line) {
  char *fields[16] = {0};
  const size_t field_count = gpsSplitLine(line, fields, 16);
  uint8_t hour = 0;
  uint8_t minute = 0;
  uint8_t second = 0;
  uint8_t day = 0;
  uint8_t month = 0;
  uint16_t year = 0;

  if (field_count < 10) {
    return;
  }

  gpsRegisterNmeaSentence();

  if (gpsParseUtcTime(fields[1], &hour, &minute, &second) &&
      gpsParseUtcDate(fields[9], &day, &month, &year)) {
    s_context.gps.hasDateTime = true;
    s_context.gps.utcHour = hour;
    s_context.gps.utcMinute = minute;
    s_context.gps.utcSecond = second;
    s_context.gps.utcDay = day;
    s_context.gps.utcMonth = month;
    s_context.gps.utcYear = year;
    s_context.gps.lastDateTimeMs = millis();
  }

  if (fields[2] == NULL || fields[2][0] != 'A') {
    return;
  }

  int32_t latitude_e7 = 0;
  int32_t longitude_e7 = 0;
  if (!gpsParseScaledDegrees(fields[3], fields[4][0], &latitude_e7) ||
      !gpsParseScaledDegrees(fields[5], fields[6][0], &longitude_e7)) {
    return;
  }

  s_context.gps.hasFix = true;
  s_context.gps.latitudeE7 = latitude_e7;
  s_context.gps.longitudeE7 = longitude_e7;
  if (s_context.gps.lastFixMs == 0) {
    s_context.gps.altitudeCm = 0;
  }
  s_context.gps.lastFixMs = millis();
}

static void gpsParseLine(char *line) {
  if (strncmp(line, "$GPGGA", 6) == 0 || strncmp(line, "$GNGGA", 6) == 0) {
    gpsApplyGga(line);
  } else if (strncmp(line, "$GPRMC", 6) == 0 ||
             strncmp(line, "$GNRMC", 6) == 0) {
    gpsApplyRmc(line);
  }
}

static void sensorsInitGps(void) {
  memset(&s_context.gps, 0, sizeof(s_context.gps));
  s_context.gps.uartOk = false;
  s_context.gpsLineLen = 0;
  s_context.gpsNmeaLogged = false;
  s_context.gpsMissingLogged = false;
  gpsClearFix();
  gpsClearDateTime();

  if (PIN_GPS_RX == PIN_RADIO0_DIO1) {
    Serial.println("[WARN] GPS RX shares the uplink DIO1 pin on this board map");
    Serial.println(
        "[WARN] GPS UART disabled, using zero-coordinate fallback");
    return;
  }

  const bool tx_ok = Serial1.setTX(PIN_GPS_TX);
  const bool rx_ok = Serial1.setRX(PIN_GPS_RX);
  if (!tx_ok || !rx_ok) {
    Serial.println("[ERROR] GPS UART pin map rejected by core");
    return;
  }

  Serial1.begin(GPS_BAUD_RATE);
  s_context.gps.uartOk = true;
  Serial.printf("[INFO] GPS UART configured at %d baud\r\n", GPS_BAUD_RATE);
}

void sensorsConfigure(void) {
  Wire.setSDA(PIN_I2C_SDA);
  Wire.setSCL(PIN_I2C_SCL);
  Wire.begin();

  s_context.bmeOk = true;
  s_context.accOk = true;

  sensorsInitAcc();
  sensorsInitBme();
  sensorsInitGps();
}

bool accelerometerRead(float *x, float *y, float *z, float *temp) {
  *x = accel.getX();
  *y = accel.getY();
  *z = accel.getZ();
  *temp = accel.getTemperature();
  return s_context.accOk;
}

bool bmeRead(float *t, float *p, float *alt, float *hum) {
  *t = bme.readTemperature();
  *p = bme.readPressure() / 100.0F;
  *alt = bme.readAltitude(SEALEVELPRESSURE_HPA);
  *hum = bme.readHumidity();
  return s_context.bmeOk;
}

void gpsPoll(void) {
  if (!s_context.gps.uartOk) {
    return;
  }

  gpsRefreshAvailability();

  while (Serial1.available() > 0) {
    const char c = (char)Serial1.read();
    s_context.gps.lastByteMs = millis();

    if (c == '\r') {
      continue;
    }

    if (c == '\n') {
      s_context.gpsLine[s_context.gpsLineLen] = '\0';
      if (s_context.gpsLineLen > 0) {
        gpsParseLine(s_context.gpsLine);
      }
      s_context.gpsLineLen = 0;
      continue;
    }

    if (s_context.gpsLineLen + 1 >= sizeof(s_context.gpsLine)) {
      s_context.gpsLineLen = 0;
      continue;
    }

    s_context.gpsLine[s_context.gpsLineLen++] = c;
  }

  gpsRefreshAvailability();
}

bool gpsRead(gps_nav_t *nav) {
  if (nav == NULL) {
    return false;
  }

  gpsRefreshAvailability();
  *nav = s_context.gps;

  if (!nav->connected || !nav->nmeaActive) {
    nav->hasFix = false;
    nav->hasDateTime = false;
    nav->latitudeE7 = 0;
    nav->longitudeE7 = 0;
    nav->altitudeCm = 0;
    nav->satellites = 0;
    nav->utcHour = 0;
    nav->utcMinute = 0;
    nav->utcSecond = 0;
    nav->utcDay = 0;
    nav->utcMonth = 0;
    nav->utcYear = 0;
    return nav->uartOk;
  }

  if (nav->lastFixMs == 0 || (millis() - nav->lastFixMs) > GPS_FIX_TIMEOUT_MS) {
    nav->hasFix = false;
    nav->latitudeE7 = 0;
    nav->longitudeE7 = 0;
    nav->altitudeCm = 0;
    nav->satellites = 0;
  }
  if (nav->lastDateTimeMs == 0 ||
      (millis() - nav->lastDateTimeMs) > GPS_NMEA_TIMEOUT_MS) {
    nav->hasDateTime = false;
    nav->utcHour = 0;
    nav->utcMinute = 0;
    nav->utcSecond = 0;
    nav->utcDay = 0;
    nav->utcMonth = 0;
    nav->utcYear = 0;
  }

  return nav->uartOk;
}

uint8_t gpsStatusByte(const gps_nav_t *nav) {
  uint8_t flags = 0;

  if (nav == NULL) {
    return 0;
  }
  if (nav->uartOk) {
    flags |= GPS_STATUS_UART_OK;
  }
  if (nav->connected) {
    flags |= GPS_STATUS_CONNECTED;
  }
  if (nav->nmeaActive) {
    flags |= GPS_STATUS_NMEA_ACTIVE;
  }
  if (nav->hasFix) {
    flags |= GPS_STATUS_FIX_VALID;
  }
  if (nav->hasDateTime) {
    flags |= GPS_STATUS_TIME_VALID;
  }
  return flags;
}

uint8_t sensorsStatusFlags(void) {
  uint8_t flags = 0;
  gps_nav_t nav = {0};

  if (s_context.bmeOk) {
    flags |= MISSION_FLAG_BME_OK;
  }
  if (s_context.accOk) {
    flags |= MISSION_FLAG_ACC_OK;
  }
  if (!gpsRead(&nav)) {
    return flags;
  }

  if (nav.uartOk) {
    flags |= MISSION_FLAG_GPS_UART_OK;
  }
  if (nav.hasFix) {
    flags |= MISSION_FLAG_GPS_FIX;
  }
  if (nav.nmeaActive) {
    flags |= MISSION_FLAG_GPS_NMEA_ACTIVE;
  }
  return flags;
}
