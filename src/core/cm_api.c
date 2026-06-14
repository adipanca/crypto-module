#include "cm_api.h"
#include "cm_entropy.h"
#include "cm_fsm.h"
#include "cm_selftest.h"
#include "cm_secure_mem.h"
#include "aes256.h"
#include "ctr_drbg.h"
#include "ecdh_p256.h"
#include "hmac_sha256.h"
#include "mlkem.h"
#include "sha256.h"
#include <stdlib.h>
#include <string.h>

static cm_module_ctx_t g_ctx = {0};

cm_status_t cm_module_init(void) {
  uint8_t seed[32];
  cm_status_t post_status;
  memset(&g_ctx, 0, sizeof(g_ctx));
  cm_set_state(&g_ctx, POWER_ON);

  cm_set_state(&g_ctx, SELF_TEST);
  post_status = cm_run_post();
  if (post_status != CM_OK) {
    g_ctx.error_code = 0x1001;
    cm_set_state(&g_ctx, ERROR_STATE);
    return post_status;
  }

  for (size_t i = 0; i < sizeof(seed); i++) seed[i] = (uint8_t)(0xA0U + i);
  ctr_drbg_init(&g_ctx.drbg, seed);

  for (size_t i = 0; i < 64; i++) {
    cm_status_t st = cm_entropy_update(&g_ctx.health, (uint8_t)i);
    if (st != CM_OK) {
      cm_set_state(&g_ctx, ERROR_STATE);
      return CM_ERR_ENTROPY;
    }
  }

  g_ctx.selftest_done = 1;
  g_ctx.integrity_ok = 1;
  g_ctx.entropy_ok = 1;
  cm_set_state(&g_ctx, INITIALIZED);
  return CM_OK;
}

cm_status_t cm_module_shutdown(void) {
  /* Zeroization eksplisit seluruh state sensitif (DRBG key/V, health state,
   * flag), bukan sekadar memset, agar tidak dioptimasi compiler. */
  secure_zero(&g_ctx, sizeof(g_ctx));
  cm_set_state(&g_ctx, POWER_OFF);
  return CM_OK;
}

cm_status_t cm_encrypt_aes256_cbc(
    const uint8_t key[32], const uint8_t iv[16],
    const uint8_t *pt, size_t pt_len,
    uint8_t *ct, size_t *ct_len) {
  if (!cm_is_operational(&g_ctx)) return CM_ERR_STATE;
  return (aes256_cbc_encrypt(key, iv, pt, pt_len, ct, ct_len) == 0) ? CM_OK : CM_ERR_CRYPTO;
}

cm_status_t cm_decrypt_aes256_cbc(
    const uint8_t key[32], const uint8_t iv[16],
    const uint8_t *ct, size_t ct_len,
    uint8_t *pt, size_t *pt_len) {
  if (!cm_is_operational(&g_ctx)) return CM_ERR_STATE;
  return (aes256_cbc_decrypt(key, iv, ct, ct_len, pt, pt_len) == 0) ? CM_OK : CM_ERR_CRYPTO;
}

cm_status_t cm_sha256(const uint8_t *in, size_t in_len, uint8_t out[32]) {
  if (!in || !out) return CM_ERR_PARAM;
  sha256_compute(in, in_len, out);
  return CM_OK;
}

cm_status_t cm_hmac_sha256(
    const uint8_t *key, size_t key_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t tag[32]) {
  if (!key || !msg || !tag) return CM_ERR_PARAM;
  hmac_sha256_compute(key, key_len, msg, msg_len, tag);
  return CM_OK;
}

cm_status_t cm_drbg_generate(uint8_t *out, size_t out_len) {
  if (!cm_is_operational(&g_ctx)) return CM_ERR_STATE;
  return (ctr_drbg_generate(&g_ctx.drbg, out, out_len) == 0) ? CM_OK : CM_ERR_CRYPTO;
}

cm_status_t cm_ecdh_p256_keygen(uint8_t priv[32], uint8_t pub[65]) {
  if (!cm_is_operational(&g_ctx)) return CM_ERR_STATE;
  return (ecdh_p256_keygen(priv, pub) == 0) ? CM_OK : CM_ERR_CRYPTO;
}

cm_status_t cm_ecdh_p256_shared(
    const uint8_t priv[32], const uint8_t peer_pub[65], uint8_t shared[32]) {
  if (!cm_is_operational(&g_ctx)) return CM_ERR_STATE;
  return (ecdh_p256_shared(priv, peer_pub, shared) == 0) ? CM_OK : CM_ERR_CRYPTO;
}

cm_status_t cm_hybrid_derive_shared(
    const uint8_t ecdh_secret[32],
    const uint8_t *mlkem_secret, size_t mlkem_secret_len,
    uint8_t hybrid_shared[32]) {
  uint8_t *concat = NULL;

  if (!ecdh_secret || !mlkem_secret || !hybrid_shared) return CM_ERR_PARAM;
  if (mlkem_secret_len == 0) return CM_ERR_PARAM;

  concat = (uint8_t *)malloc(32U + mlkem_secret_len);
  if (!concat) return CM_ERR_CRYPTO;

  memcpy(concat, ecdh_secret, 32U);
  memcpy(concat + 32U, mlkem_secret, mlkem_secret_len);
  sha256_compute(concat, 32U + mlkem_secret_len, hybrid_shared);
  /* Zeroize buffer gabungan secret sebelum dibebaskan. */
  secure_zero(concat, 32U + mlkem_secret_len);
  free(concat);
  return CM_OK;
}

cm_status_t cm_hybrid_ecdh_mlkem_shared(
    const uint8_t priv[32], const uint8_t peer_pub[65],
    const uint8_t *mlkem_secret, size_t mlkem_secret_len,
    uint8_t hybrid_shared[32]) {
  uint8_t ecdh_secret[32];
  cm_status_t st;

  if (!cm_is_operational(&g_ctx)) return CM_ERR_STATE;

  st = cm_ecdh_p256_shared(priv, peer_pub, ecdh_secret);
  if (st != CM_OK) return st;

  st = cm_hybrid_derive_shared(ecdh_secret, mlkem_secret, mlkem_secret_len, hybrid_shared);
  /* Zeroize ECDH shared secret intermediate setelah dipakai. */
  secure_zero(ecdh_secret, sizeof(ecdh_secret));
  return st;
}

cm_status_t cm_mlkem_keygen(uint8_t *pk, size_t *pk_len, uint8_t *sk, size_t *sk_len) {
  int rc;
  if (!cm_is_operational(&g_ctx)) return CM_ERR_STATE;
  rc = mlkem_keygen(pk, pk_len, sk, sk_len);
  if (rc == 1) return CM_ERR_STATE; /* ML-KEM tidak tersedia */
  return (rc == 0) ? CM_OK : CM_ERR_CRYPTO;
}

cm_status_t cm_mlkem_encaps(const uint8_t *pk, size_t pk_len,
                            uint8_t *ct, size_t *ct_len,
                            uint8_t *ss, size_t *ss_len) {
  int rc;
  if (!cm_is_operational(&g_ctx)) return CM_ERR_STATE;
  rc = mlkem_encaps(pk, pk_len, ct, ct_len, ss, ss_len);
  if (rc == 1) return CM_ERR_STATE;
  return (rc == 0) ? CM_OK : CM_ERR_CRYPTO;
}

cm_status_t cm_mlkem_decaps(const uint8_t *sk, size_t sk_len,
                            const uint8_t *ct, size_t ct_len,
                            uint8_t *ss, size_t *ss_len) {
  int rc;
  if (!cm_is_operational(&g_ctx)) return CM_ERR_STATE;
  rc = mlkem_decaps(sk, sk_len, ct, ct_len, ss, ss_len);
  if (rc == 1) return CM_ERR_STATE;
  return (rc == 0) ? CM_OK : CM_ERR_CRYPTO;
}
