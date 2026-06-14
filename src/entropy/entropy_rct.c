#include "cm_entropy.h"
#include <stdlib.h>
#include <string.h>

cm_status_t cm_entropy_update(entropy_health_t *h, uint8_t sample) {
  if (!h) return CM_ERR_PARAM;
  if (getenv("CM_FORCE_ENTROPY_FAIL")) return CM_ERR_ENTROPY;

  if (h->seen == 0) {
    h->last = sample;
    h->repeat = 1;
  } else {
    h->repeat = (sample == h->last) ? (h->repeat + 1U) : 1U;
    h->last = sample;
  }
  if (h->repeat >= RCT_CUTOFF) return CM_ERR_ENTROPY;

  h->hist[sample]++;
  h->seen++;

  if (h->seen == APT_W) {
    uint32_t maxv = 0;
    for (size_t i = 0; i < 256; i++) {
      if (h->hist[i] > maxv) maxv = h->hist[i];
    }
    if (maxv >= APT_CUTOFF) return CM_ERR_ENTROPY;
    memset(h->hist, 0, sizeof(h->hist));
    h->seen = 0;
  }
  return CM_OK;
}
