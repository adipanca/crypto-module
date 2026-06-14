#include "mlkem.h"
#include "cm_secure_mem.h"

#include <openssl/evp.h>
#include <string.h>

#if defined(OPENSSL_VERSION_MAJOR) && (OPENSSL_VERSION_MAJOR >= 3)
#include <openssl/core_names.h>
#include <openssl/params.h>

#define MLKEM_ALG_NAME "ML-KEM-768"

int mlkem_available(void) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, MLKEM_ALG_NAME, NULL);
  if (!ctx) return 0;
  EVP_PKEY_CTX_free(ctx);
  return 1;
}

int mlkem_keygen(uint8_t *pk, size_t *pk_len, uint8_t *sk, size_t *sk_len) {
  EVP_PKEY_CTX *ctx = NULL;
  EVP_PKEY *key = NULL;
  size_t pub_out = 0;
  size_t priv_out = 0;
  int rc = -1;

  if (!pk || !pk_len || !sk || !sk_len) return -1;
  if (!mlkem_available()) return 1;

  ctx = EVP_PKEY_CTX_new_from_name(NULL, MLKEM_ALG_NAME, NULL);
  if (!ctx) return 1;

  if (EVP_PKEY_keygen_init(ctx) <= 0) goto done;
  if (EVP_PKEY_generate(ctx, &key) <= 0 || !key) goto done;

  if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY,
                                      pk, MLKEM768_PUB_LEN, &pub_out) <= 0)
    goto done;
  if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PRIV_KEY,
                                      sk, MLKEM768_PRIV_LEN, &priv_out) <= 0)
    goto done;

  *pk_len = pub_out;
  *sk_len = priv_out;
  rc = 0;

done:
  EVP_PKEY_free(key);
  EVP_PKEY_CTX_free(ctx);
  return rc;
}

int mlkem_encaps(const uint8_t *pk, size_t pk_len,
                 uint8_t *ct, size_t *ct_len,
                 uint8_t *ss, size_t *ss_len) {
  EVP_PKEY_CTX *import_ctx = NULL;
  EVP_PKEY_CTX *enc_ctx = NULL;
  EVP_PKEY *pub = NULL;
  size_t ct_cap = 0;
  size_t ss_cap = 0;
  int rc = -1;

  if (!pk || !ct || !ct_len || !ss || !ss_len) return -1;
  if (!mlkem_available()) return 1;

  OSSL_PARAM params[] = {
      OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)pk, pk_len),
      OSSL_PARAM_END};

  import_ctx = EVP_PKEY_CTX_new_from_name(NULL, MLKEM_ALG_NAME, NULL);
  if (!import_ctx) return 1;
  if (EVP_PKEY_fromdata_init(import_ctx) <= 0) goto done;
  if (EVP_PKEY_fromdata(import_ctx, &pub, EVP_PKEY_PUBLIC_KEY, params) <= 0 || !pub)
    goto done;

  enc_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pub, NULL);
  if (!enc_ctx) goto done;
  if (EVP_PKEY_encapsulate_init(enc_ctx, NULL) <= 0) goto done;

  if (EVP_PKEY_encapsulate(enc_ctx, NULL, &ct_cap, NULL, &ss_cap) <= 0) goto done;
  if (ct_cap > *ct_len || ss_cap > *ss_len) goto done;

  if (EVP_PKEY_encapsulate(enc_ctx, ct, &ct_cap, ss, &ss_cap) <= 0) goto done;

  *ct_len = ct_cap;
  *ss_len = ss_cap;
  rc = 0;

done:
  EVP_PKEY_free(pub);
  EVP_PKEY_CTX_free(enc_ctx);
  EVP_PKEY_CTX_free(import_ctx);
  return rc;
}

int mlkem_decaps(const uint8_t *sk, size_t sk_len,
                 const uint8_t *ct, size_t ct_len,
                 uint8_t *ss, size_t *ss_len) {
  EVP_PKEY_CTX *import_ctx = NULL;
  EVP_PKEY_CTX *dec_ctx = NULL;
  EVP_PKEY *priv = NULL;
  size_t ss_cap = 0;
  int rc = -1;

  if (!sk || !ct || !ss || !ss_len) return -1;
  if (!mlkem_available()) return 1;

  OSSL_PARAM params[] = {
      OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, (void *)sk, sk_len),
      OSSL_PARAM_END};

  import_ctx = EVP_PKEY_CTX_new_from_name(NULL, MLKEM_ALG_NAME, NULL);
  if (!import_ctx) return 1;
  if (EVP_PKEY_fromdata_init(import_ctx) <= 0) goto done;
  if (EVP_PKEY_fromdata(import_ctx, &priv, EVP_PKEY_KEYPAIR, params) <= 0 || !priv)
    goto done;

  dec_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, priv, NULL);
  if (!dec_ctx) goto done;
  if (EVP_PKEY_decapsulate_init(dec_ctx, NULL) <= 0) goto done;

  ss_cap = *ss_len;
  if (EVP_PKEY_decapsulate(dec_ctx, ss, &ss_cap, ct, ct_len) <= 0) goto done;

  *ss_len = ss_cap;
  rc = 0;

done:
  EVP_PKEY_free(priv);
  EVP_PKEY_CTX_free(dec_ctx);
  EVP_PKEY_CTX_free(import_ctx);
  return rc;
}

#else /* OpenSSL < 3 : ML-KEM tidak tersedia */

int mlkem_available(void) { return 0; }

int mlkem_keygen(uint8_t *pk, size_t *pk_len, uint8_t *sk, size_t *sk_len) {
  (void)pk; (void)pk_len; (void)sk; (void)sk_len;
  return 1;
}

int mlkem_encaps(const uint8_t *pk, size_t pk_len,
                 uint8_t *ct, size_t *ct_len,
                 uint8_t *ss, size_t *ss_len) {
  (void)pk; (void)pk_len; (void)ct; (void)ct_len; (void)ss; (void)ss_len;
  return 1;
}

int mlkem_decaps(const uint8_t *sk, size_t sk_len,
                 const uint8_t *ct, size_t ct_len,
                 uint8_t *ss, size_t *ss_len) {
  (void)sk; (void)sk_len; (void)ct; (void)ct_len; (void)ss; (void)ss_len;
  return 1;
}

#endif
