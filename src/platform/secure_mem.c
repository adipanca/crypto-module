#include "cm_secure_mem.h"
#include <stdint.h>

void secure_zero(void *ptr, size_t len) {
  volatile uint8_t *p = (volatile uint8_t *)ptr;
  if (!ptr) return;
  while (len--) *p++ = 0;
}
