#ifndef CM_TYPES_H
#define CM_TYPES_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
  POWER_OFF = 0,
  POWER_ON,
  SELF_TEST,
  INITIALIZED,
  KEY_GENERATION,
  KEY_EXCHANGE,
  ENCRYPTION,
  DECRYPTION,
  ERROR_STATE
} cm_state_t;

typedef struct {
  uint8_t key[32];
  uint8_t v[16];
  uint64_t reseed_counter;
  uint8_t instantiated;
} ctr_drbg_ctx_t;

typedef struct {
  uint8_t last;
  uint32_t repeat;
  uint32_t hist[256];
  uint32_t seen;
} entropy_health_t;

typedef struct {
  cm_state_t state;
  uint32_t error_code;
  uint8_t selftest_done;
  uint8_t integrity_ok;
  uint8_t entropy_ok;
  ctr_drbg_ctx_t drbg;
  entropy_health_t health;
} cm_module_ctx_t;

#endif
