#ifndef CM_ENTROPY_H
#define CM_ENTROPY_H

#include "cm_error.h"
#include "cm_types.h"
#include <stdint.h>

#define RCT_CUTOFF 21
#define APT_W 512
#define APT_CUTOFF 311

cm_status_t cm_entropy_update(entropy_health_t *h, uint8_t sample);

#endif
