/*  - regions.h
 *
 * firmware - By astrobyte 18/03/26.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * ISM region selection. A build-time macro from platformio.ini
 * (FLATSAT_REGION_US915 / _EU868 / _EU433 / _AS923) picks the uplink
 * and downlink center frequencies. Either preset can be overridden by
 * defining FLATSAT_UPLINK_FREQ_KHZ / FLATSAT_DOWNLINK_FREQ_KHZ
 * directly on the command line (kHz gives sub-MHz precision, needed
 * for EU433 -- see below). Falls back to US915, the historical
 * hardcoded values.
 *
 * The Attacks/ side mirrors this file (lib/regions.py); if you add
 * a region here, add it there too so TX/RX stay aligned.
 *
 * Every preset keeps a +2 MHz uplink/downlink split (uplink 2 MHz
 * above downlink) EXCEPT EU433: the strict CEPT ISM 433.05-434.79 MHz
 * window is only ~1.74 MHz wide, so EU433 uses a +1 MHz split with
 * both centers on half-MHz boundaries to fit a 250 kHz channel BW
 * cleanly in-band on both sides.
 */
#ifndef FIRMWARE_REGIONS_H
#define FIRMWARE_REGIONS_H

#if defined(FLATSAT_REGION_EU868)
  #ifndef FLATSAT_UPLINK_FREQ_KHZ
    #define FLATSAT_UPLINK_FREQ_KHZ 869000
  #endif
  #ifndef FLATSAT_DOWNLINK_FREQ_KHZ
    #define FLATSAT_DOWNLINK_FREQ_KHZ 867000
  #endif
#elif defined(FLATSAT_REGION_EU433)
  #ifndef FLATSAT_UPLINK_FREQ_KHZ
    #define FLATSAT_UPLINK_FREQ_KHZ 434500
  #endif
  #ifndef FLATSAT_DOWNLINK_FREQ_KHZ
    #define FLATSAT_DOWNLINK_FREQ_KHZ 433500
  #endif
#elif defined(FLATSAT_REGION_AS923)
  #ifndef FLATSAT_UPLINK_FREQ_KHZ
    #define FLATSAT_UPLINK_FREQ_KHZ 924000
  #endif
  #ifndef FLATSAT_DOWNLINK_FREQ_KHZ
    #define FLATSAT_DOWNLINK_FREQ_KHZ 922000
  #endif
#else
  #ifndef FLATSAT_UPLINK_FREQ_KHZ
    #define FLATSAT_UPLINK_FREQ_KHZ 918000
  #endif
  #ifndef FLATSAT_DOWNLINK_FREQ_KHZ
    #define FLATSAT_DOWNLINK_FREQ_KHZ 916000
  #endif
#endif

#endif // FIRMWARE_REGIONS_H
