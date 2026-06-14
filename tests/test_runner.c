#include "cm_api.h"
#include "cm_error.h"
#include <stdio.h>

static int test_init(void) {
  cm_status_t st = cm_module_init();
  printf("Input: cm_module_init\nExpected Output: CM_OK\nResult Output: %s\n", cm_status_str(st));
  if (st != CM_OK) {
    printf("[FAIL] cm_module_init: %s\n", cm_status_str(st));
    return 1;
  }
  printf("[PASS] cm_module_init\n");
  return 0;
}

static int test_kat(void) {
  cm_status_t st = cm_run_kat_all();
  printf("\nInput: cm_run_kat_all\nExpected Output: CM_OK\nResult Output: %s\n", cm_status_str(st));
  if (st != CM_OK) {
    printf("[FAIL] cm_run_kat_all: %s\n", cm_status_str(st));
    return 1;
  }
  printf("[PASS] cm_run_kat_all\n");
  return 0;
}

static int test_drbg(void) {
  uint8_t out[16];
  cm_status_t st = cm_drbg_generate(out, sizeof(out));
  printf("\nInput: cm_drbg_generate(16 bytes)\nExpected Output: CM_OK dan output acak 16 byte\nResult Output: %s\n", cm_status_str(st));
  if (st != CM_OK) {
    printf("[FAIL] cm_drbg_generate: %s\n", cm_status_str(st));
    return 1;
  }
  printf("[PASS] cm_drbg_generate\n");
  return 0;
}

int main(void) {
  int fail = 0;
  fail |= test_init();
  fail |= test_kat();
  fail |= test_drbg();
  cm_module_shutdown();

  if (fail) {
    printf("\nTest result: FAIL\n");
    return 1;
  }
  printf("\nTest result: PASS\n");
  return 0;
}
