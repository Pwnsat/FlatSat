/*  - main.ino
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#include "led.h"
#include "rdownlink.h"
#include "ruplink.h"
#include "sensors.h"
#include "spacecan.h"
#include "usbCDC.h"
#include "worker.h"

typedef struct {
  const unsigned long inverval;
  unsigned long previous;
} timeout_worker_t_t;

static timeout_worker_t_t t_tra = {.inverval = 5000, .previous = 0};

void setup() {
  obcSetupUSB();
  ledConfigure();
  obcConfigureCore0();
  sensorsConfigure();
  uplinkRadioConfigure();
  downlinkRadioConfigure();
  uplinkRadioRegisterCb(commandHandlerRadio);
  obcUSBPacketRecivedCallback(commandHandlerUSB);
  ledTurnWhite();
  delay(500);
  ledTurnOff();
}

void setup1() { obcConfigureCore1(); }

void loop() {
  gpsPoll();
  uplinkRadioCheckPacketReceived();
  downlinkRadioCheckTransmition();
  telemetryRadioWorker();
  if (consoleSensorModeActive()) {
    telemetryDashboardWorker();
  }
  consoleWorker();
}

void loop1() { obcUSBRecv(); }
