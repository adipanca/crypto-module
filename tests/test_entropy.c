#include "cm_entropy.h"
#include "cm_error.h"
#include "cm_types.h"
#include <stdio.h>
#include <string.h>

int main(void) {
  entropy_health_t h;
  int fail_index = -1;
  memset(&h, 0, sizeof(h));

  printf("Entropy Test A (normal stream)\n");
  printf("Input: sampel meningkat 0..127\n");
  printf("Expected Output: semua update = CM_OK\n");
  for (int i = 0; i < 128; i++) {
    cm_status_t st = cm_entropy_update(&h, (uint8_t)i);
    if (st != CM_OK) {
      printf("[FAIL] entropy update unexpectedly failed at i=%d\n", i);
      return 1;
    }
  }
  printf("Result Output: semua update CM_OK\n\n");

  memset(&h, 0, sizeof(h));
  printf("Entropy Test B (RCT threshold)\n");
  printf("Input: sampel berulang 0xAA sebanyak RCT_CUTOFF kali\n");
  printf("Expected Output: gagal tepat saat i = RCT_CUTOFF-1 dengan CM_ERR_ENTROPY\n");
  for (int i = 0; i < RCT_CUTOFF; i++) {
    cm_status_t st = cm_entropy_update(&h, 0xAA);
    if (i < (RCT_CUTOFF - 1) && st != CM_OK) {
      printf("[FAIL] early RCT fail at i=%d\n", i);
      return 1;
    }
    if (i == (RCT_CUTOFF - 1) && st != CM_ERR_ENTROPY) {
      printf("[FAIL] expected RCT failure at threshold\n");
      return 1;
    }
    if (st == CM_ERR_ENTROPY) fail_index = i;
  }
  printf("Result Output: gagal pada i=%d dengan CM_ERR_ENTROPY\n", fail_index);

  printf("[PASS] entropy test (normal + RCT threshold)\n");
  return 0;
}
