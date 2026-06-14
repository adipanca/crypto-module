#ifndef CM_SELFTEST_H
#define CM_SELFTEST_H

#include "cm_error.h"

cm_status_t kat_aes256(void);
cm_status_t kat_sha256(void);
cm_status_t kat_hmac_sha256(void);
cm_status_t kat_ctr_drbg(void);
cm_status_t kat_ecdh_p256(void);
cm_status_t cm_run_kat_all(void);
cm_status_t cm_run_post(void);
cm_status_t cm_run_conditional_test(void);

#endif
