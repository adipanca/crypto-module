#include <stdint.h>
#include <stdlib.h>

int platform_get_random(uint8_t *out, size_t len) {
  if (!out) return -1;
  for (size_t i = 0; i < len; i++) out[i] = (uint8_t)(rand() & 0xFF);
  return 0;
}
