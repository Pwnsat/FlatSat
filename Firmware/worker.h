/*  - worker.h
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#ifndef FIRMWARE_WORKER_H
#define FIRMWARE_WORKER_H
#include <Arduino.h>

void telemetrySCWorker(void);
void telemetryRadioWorker(void);
void telemetryDashboardWorker(void);
void commandHandler(uint8_t *buffer, uint16_t buffer_len);
void commandHandlerRadio(uint8_t *buffer, uint16_t buffer_len);
void commandHandlerUSB(uint8_t *buffer, uint16_t buffer_len);
#endif // FIRMWARE_WORKER_H
