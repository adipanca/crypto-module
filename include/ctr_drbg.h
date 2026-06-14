#ifndef CTR_DRBG_H
#define CTR_DRBG_H

#include "cm_types.h"
#include <stddef.h>
#include <stdint.h>

/*
 * CTR_DRBG berbasis AES-256 tanpa derivation function (no df),
 * mengikuti konstruksi NIST SP 800-90A.
 *   seedlen = keylen(32) + blocklen(16) = 48 byte
 */

/* Seeding sederhana untuk runtime: seed 32 byte diperluas menjadi
 * seed_material 48 byte lalu di-update sesuai SP 800-90A. */
void ctr_drbg_init(ctr_drbg_ctx_t *ctx, const uint8_t seed[32]);

/* Instantiate sesuai SP 800-90A dengan entropy_input || nonce ||
 * personalization. Total panjang harus tepat 48 byte (seedlen).
 * Mengembalikan 0 jika sukses, -1 jika gagal. */
int ctr_drbg_instantiate(ctr_drbg_ctx_t *ctx,
                         const uint8_t *entropy, size_t entropy_len,
                         const uint8_t *nonce, size_t nonce_len,
                         const uint8_t *perso, size_t perso_len);

int ctr_drbg_generate(ctr_drbg_ctx_t *ctx, uint8_t *out, size_t out_len);

#endif
