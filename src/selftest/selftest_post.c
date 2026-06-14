#include "cm_selftest.h"
#include "cm_integrity.h"
#include <stdlib.h>

cm_status_t cm_run_kat_all(void) {
  if (getenv("CM_FORCE_KAT_FAIL")) return CM_ERR_SELFTEST;
  if (kat_aes256() != CM_OK) return CM_ERR_SELFTEST;
  if (kat_sha256() != CM_OK) return CM_ERR_SELFTEST;
  if (kat_hmac_sha256() != CM_OK) return CM_ERR_SELFTEST;
  if (kat_ctr_drbg() != CM_OK) return CM_ERR_SELFTEST;
  if (kat_ecdh_p256() != CM_OK) return CM_ERR_SELFTEST;
  return CM_OK;
}

cm_status_t cm_run_post(void) {
  if (cm_run_integrity_check() != CM_OK) return CM_ERR_INTEGRITY;
  if (cm_run_kat_all() != CM_OK) return CM_ERR_SELFTEST;
  if (cm_run_conditional_test() != CM_OK) return CM_ERR_SELFTEST;
  return CM_OK;
}
