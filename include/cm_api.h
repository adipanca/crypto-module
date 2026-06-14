#ifndef CM_API_H
#define CM_API_H

#include "cm_error.h"
#include <stddef.h>
#include <stdint.h>

cm_status_t cm_module_init(void);
cm_status_t cm_module_shutdown(void);

cm_status_t cm_encrypt_aes256_cbc(
    const uint8_t key[32], const uint8_t iv[16],
    const uint8_t *pt, size_t pt_len,
    uint8_t *ct, size_t *ct_len);

cm_status_t cm_decrypt_aes256_cbc(
    const uint8_t key[32], const uint8_t iv[16],
    const uint8_t *ct, size_t ct_len,
    uint8_t *pt, size_t *pt_len);

cm_status_t cm_sha256(const uint8_t *in, size_t in_len, uint8_t out[32]);

cm_status_t cm_hmac_sha256(
    const uint8_t *key, size_t key_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t tag[32]);

cm_status_t cm_drbg_generate(uint8_t *out, size_t out_len);

cm_status_t cm_ecdh_p256_keygen(uint8_t priv[32], uint8_t pub[65]);
cm_status_t cm_ecdh_p256_shared(
    const uint8_t priv[32], const uint8_t peer_pub[65], uint8_t shared[32]);

cm_status_t cm_hybrid_derive_shared(
    const uint8_t ecdh_secret[32],
    const uint8_t *mlkem_secret, size_t mlkem_secret_len,
    uint8_t hybrid_shared[32]);

cm_status_t cm_hybrid_ecdh_mlkem_shared(
    const uint8_t priv[32], const uint8_t peer_pub[65],
    const uint8_t *mlkem_secret, size_t mlkem_secret_len,
    uint8_t hybrid_shared[32]);

/* ML-KEM-768 (FIPS 203): keygen / encapsulation / decapsulation.
 * Mengembalikan CM_OK saat sukses, CM_ERR_CRYPTO saat gagal, dan
 * CM_ERR_STATE bila ML-KEM tidak tersedia pada provider OpenSSL. */
cm_status_t cm_mlkem_keygen(uint8_t *pk, size_t *pk_len, uint8_t *sk, size_t *sk_len);

cm_status_t cm_mlkem_encaps(const uint8_t *pk, size_t pk_len,
                            uint8_t *ct, size_t *ct_len,
                            uint8_t *ss, size_t *ss_len);

cm_status_t cm_mlkem_decaps(const uint8_t *sk, size_t sk_len,
                            const uint8_t *ct, size_t ct_len,
                            uint8_t *ss, size_t *ss_len);

cm_status_t cm_run_post(void);
cm_status_t cm_run_kat_all(void);
cm_status_t cm_run_integrity_check(void);

#endif
