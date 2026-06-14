#include "cm_api.h"
#include "cm_error.h"
#include <stdio.h>

int main(void) {
  uint8_t out[16];
  cm_status_t st;

  st = cm_drbg_generate(out, sizeof(out));
  printf("FSM Check 1\nInput: cm_drbg_generate sebelum init\nExpected Output: CM_ERR_STATE\nResult Output: %s\n", cm_status_str(st));
  if (st != CM_ERR_STATE) {
    printf("[FAIL] expected CM_ERR_STATE before init, got %s\n", cm_status_str(st));
    return 1;
  }

  st = cm_module_init();
  printf("\nFSM Check 2\nInput: cm_module_init\nExpected Output: CM_OK\nResult Output: %s\n", cm_status_str(st));
  if (st != CM_OK) {
    printf("[FAIL] cm_module_init: %s\n", cm_status_str(st));
    return 1;
  }

  st = cm_drbg_generate(out, sizeof(out));
  printf("\nFSM Check 3\nInput: cm_drbg_generate setelah init\nExpected Output: CM_OK\nResult Output: %s\n", cm_status_str(st));
  if (st != CM_OK) {
    printf("[FAIL] expected CM_OK after init, got %s\n", cm_status_str(st));
    return 1;
  }

  cm_module_shutdown();
  printf("[PASS] FSM gate checks\n");
  return 0;
}
