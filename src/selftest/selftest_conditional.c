#include "cm_selftest.h"
#include "cm_entropy.h"
#include "cm_types.h"
#include <stdlib.h>
#include <string.h>

cm_status_t cm_run_conditional_test(void) {
  entropy_health_t h;
  memset(&h, 0, sizeof(h));

  if (getenv("CM_FORCE_CONDITIONAL_FAIL")) return CM_ERR_SELFTEST;

  for (int i = 0; i < 64; i++) {
    if (cm_entropy_update(&h, (uint8_t)i) != CM_OK) return CM_ERR_SELFTEST;
  }

  return CM_OK;
}
