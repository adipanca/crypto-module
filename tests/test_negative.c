#include "cm_api.h"
#include "cm_error.h"
#include <stdio.h>
#include <stdlib.h>

static int test_kat_fail_injection(void) {
  cm_status_t st;
  setenv("CM_FORCE_KAT_FAIL", "1", 1);
  st = cm_module_init();
  unsetenv("CM_FORCE_KAT_FAIL");
  printf("KAT Fail Injection\nInput: CM_FORCE_KAT_FAIL=1\nExpected Output: CM_ERR_SELFTEST\nResult Output: %s\n", cm_status_str(st));
  if (st != CM_ERR_SELFTEST) {
    printf("[FAIL] expected CM_ERR_SELFTEST for KAT injection, got %s\n", cm_status_str(st));
    return 1;
  }
  printf("[PASS] KAT fail injection\n");
  return 0;
}

static int test_entropy_fail_injection(void) {
  cm_status_t st;
  setenv("CM_FORCE_ENTROPY_FAIL", "1", 1);
  st = cm_module_init();
  unsetenv("CM_FORCE_ENTROPY_FAIL");
  printf("\nEntropy Fail Injection\nInput: CM_FORCE_ENTROPY_FAIL=1\nExpected Output: CM_ERR_ENTROPY atau CM_ERR_SELFTEST\nResult Output: %s\n", cm_status_str(st));
  if (!(st == CM_ERR_ENTROPY || st == CM_ERR_SELFTEST)) {
    printf("[FAIL] expected CM_ERR_ENTROPY or CM_ERR_SELFTEST for entropy injection, got %s\n", cm_status_str(st));
    return 1;
  }
  printf("[PASS] entropy fail injection\n");
  return 0;
}

static int test_integrity_fail_injection(void) {
  cm_status_t st;
  setenv("CM_FORCE_INTEGRITY_FAIL", "1", 1);
  st = cm_module_init();
  unsetenv("CM_FORCE_INTEGRITY_FAIL");
  printf("\nIntegrity Fail Injection\nInput: CM_FORCE_INTEGRITY_FAIL=1\nExpected Output: CM_ERR_INTEGRITY\nResult Output: %s\n", cm_status_str(st));
  if (st != CM_ERR_INTEGRITY) {
    printf("[FAIL] expected CM_ERR_INTEGRITY for integrity injection, got %s\n", cm_status_str(st));
    return 1;
  }
  printf("[PASS] integrity fail injection\n");
  return 0;
}

int main(void) {
  int fail = 0;
  fail |= test_kat_fail_injection();
  fail |= test_entropy_fail_injection();
  fail |= test_integrity_fail_injection();
  if (fail) {
    printf("\nNegative tests: FAIL\n");
    return 1;
  }
  printf("\nNegative tests: PASS\n");
  return 0;
}
