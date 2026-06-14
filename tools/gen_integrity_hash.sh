#!/usr/bin/env bash
set -euo pipefail
BIN="$1"
OUT_C="$2"
HASH=$(shasum -a 256 "$BIN" | awk '{print $1}')
{
  echo "#include <stdint.h>"
  echo "const uint8_t g_expected_module_hash[32] = {"
  for i in $(seq 0 31); do
    b=${HASH:$((i*2)):2}
    if [ "$i" -lt 31 ]; then
      echo -n "0x$b,"
    else
      echo -n "0x$b"
    fi
  done
  echo "};"
} > "$OUT_C"
