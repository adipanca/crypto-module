#include "cm_api.h"
#include "cm_error.h"
#include <stdio.h>

int main(void) {
  cm_status_t st = cm_run_post();
  printf("Input: cm_run_post\nExpected Output: CM_OK\nResult Output: %s\n", cm_status_str(st));
  if (st != CM_OK) {
    printf("[FAIL] cm_run_post: %s\n", cm_status_str(st));
    return 1;
  }
  printf("[PASS] POST/self-test\n");
  return 0;
}
