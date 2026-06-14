#include "ctr_drbg.h"
#include "cm_secure_mem.h"
#include <openssl/evp.h>
#include <string.h>

#define CTRDRBG_SEEDLEN 48
#define CTRDRBG_KEYLEN 32
#define CTRDRBG_BLOCKLEN 16

/* AES-256 ECB satu blok (16 byte), tanpa padding. */
static int aes256_ecb_block(const uint8_t key[32], const uint8_t in[16], uint8_t out[16]) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int outl = 0;
  if (!ctx) return -1;
  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL) != 1) goto fail;
  if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) goto fail;
  if (EVP_EncryptUpdate(ctx, out, &outl, in, 16) != 1 || outl != 16) goto fail;
  EVP_CIPHER_CTX_free(ctx);
  return 0;
fail:
  EVP_CIPHER_CTX_free(ctx);
  return -1;
}

static void increment_counter(uint8_t counter[16]) {
  for (int i = 15; i >= 0; i--) {
    counter[i]++;
    if (counter[i] != 0) break;
  }
}

/* CTR_DRBG_Update (SP 800-90A) dengan provided_data sepanjang seedlen. */
static int ctr_drbg_update(ctr_drbg_ctx_t *ctx, const uint8_t provided[CTRDRBG_SEEDLEN]) {
  uint8_t temp[CTRDRBG_SEEDLEN];
  uint8_t block[CTRDRBG_BLOCKLEN];
  size_t i = 0;

  while (i < CTRDRBG_SEEDLEN) {
    increment_counter(ctx->v);
    if (aes256_ecb_block(ctx->key, ctx->v, block) != 0) {
      secure_zero(temp, sizeof(temp));
      secure_zero(block, sizeof(block));
      return -1;
    }
    size_t n = (CTRDRBG_SEEDLEN - i < CTRDRBG_BLOCKLEN) ? (CTRDRBG_SEEDLEN - i) : CTRDRBG_BLOCKLEN;
    memcpy(temp + i, block, n);
    i += n;
  }

  for (i = 0; i < CTRDRBG_SEEDLEN; i++) temp[i] ^= provided[i];
  memcpy(ctx->key, temp, CTRDRBG_KEYLEN);
  memcpy(ctx->v, temp + CTRDRBG_KEYLEN, CTRDRBG_BLOCKLEN);

  secure_zero(temp, sizeof(temp));
  secure_zero(block, sizeof(block));
  return 0;
}

int ctr_drbg_instantiate(ctr_drbg_ctx_t *ctx,
                         const uint8_t *entropy, size_t entropy_len,
                         const uint8_t *nonce, size_t nonce_len,
                         const uint8_t *perso, size_t perso_len) {
  uint8_t seed_material[CTRDRBG_SEEDLEN];
  size_t off = 0;

  if (!ctx) return -1;
  if (entropy_len + nonce_len + perso_len != CTRDRBG_SEEDLEN) return -1;

  if (entropy && entropy_len) { memcpy(seed_material + off, entropy, entropy_len); off += entropy_len; }
  if (nonce && nonce_len)     { memcpy(seed_material + off, nonce, nonce_len); off += nonce_len; }
  if (perso && perso_len)     { memcpy(seed_material + off, perso, perso_len); off += perso_len; }

  memset(ctx->key, 0, CTRDRBG_KEYLEN);
  memset(ctx->v, 0, CTRDRBG_BLOCKLEN);

  if (ctr_drbg_update(ctx, seed_material) != 0) {
    secure_zero(seed_material, sizeof(seed_material));
    return -1;
  }

  ctx->reseed_counter = 1;
  ctx->instantiated = 1;
  secure_zero(seed_material, sizeof(seed_material));
  return 0;
}

void ctr_drbg_init(ctr_drbg_ctx_t *ctx, const uint8_t seed[32]) {
  uint8_t seed_material[CTRDRBG_SEEDLEN];
  if (!ctx || !seed) return;

  /* Perluas seed 32 byte menjadi seed_material 48 byte (seedlen). */
  memcpy(seed_material, seed, 32);
  memcpy(seed_material + 32, seed, 16);

  memset(ctx->key, 0, CTRDRBG_KEYLEN);
  memset(ctx->v, 0, CTRDRBG_BLOCKLEN);
  ctx->reseed_counter = 0;
  ctx->instantiated = 0;

  if (ctr_drbg_update(ctx, seed_material) == 0) {
    ctx->reseed_counter = 1;
    ctx->instantiated = 1;
  }
  secure_zero(seed_material, sizeof(seed_material));
}

int ctr_drbg_generate(ctr_drbg_ctx_t *ctx, uint8_t *out, size_t out_len) {
  uint8_t block[CTRDRBG_BLOCKLEN];
  uint8_t zeros[CTRDRBG_SEEDLEN];
  size_t i = 0;

  if (!ctx || !out || !ctx->instantiated) return -1;

  while (i < out_len) {
    increment_counter(ctx->v);
    if (aes256_ecb_block(ctx->key, ctx->v, block) != 0) {
      secure_zero(block, sizeof(block));
      return -1;
    }
    size_t n = (out_len - i < CTRDRBG_BLOCKLEN) ? (out_len - i) : CTRDRBG_BLOCKLEN;
    memcpy(out + i, block, n);
    i += n;
  }

  memset(zeros, 0, sizeof(zeros));
  if (ctr_drbg_update(ctx, zeros) != 0) {
    secure_zero(block, sizeof(block));
    return -1;
  }
  ctx->reseed_counter++;

  secure_zero(block, sizeof(block));
  return 0;
}
