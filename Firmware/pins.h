/*  - pins.h
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#ifndef FIRMWARE_PINS_H
#define FIRMWARE_PINS_H

#define PIN_RGB_LED 15
#define PIN_BUTTON1 12
#define PIN_BUTTON2 13

/* Radio 0 */
#define PIN_SPI_RADIO0_CIPO 16 // MISO
#define PIN_SPI_RADIO0_SCK 18
#define PIN_SPI_RADIO0_COPI 19 // MOSI

#define PIN_RADIO0_NSS 17
#define PIN_RADIO0_RST 27
#define PIN_RADIO0_BSY 26
#define PIN_RADIO0_DIO1 3
#define PIN_RADIO0_DIO2 24
#define PIN_RADIO0_DIO3 25
#define PIN_RADIO0_ANT_SW 28

/* Radio 1 */
#define PIN_SPI_RADIO1_CIPO 4
#define PIN_SPI_RADIO1_SCK 6
#define PIN_SPI_RADIO1_COPI 7

#define PIN_RADIO1_NSS 5
#define PIN_RADIO1_RST 11
#define PIN_RADIO1_BSY 14
#define PIN_RADIO1_DIO1 8
#define PIN_RADIO1_DIO2 9
#define PIN_RADIO1_DIO3 10
#define PIN_RADIO1_ANT_SW 29

/* I2C */
#define PIN_I2C_SDA 20
#define PIN_I2C_SCL 21

/* GPS UART */
#define PIN_GPS_TX 0
#define PIN_GPS_RX 1
#endif // FIRMWARE_PINS_H
