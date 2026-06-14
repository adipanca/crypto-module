#include "aes256.h"
#include <openssl/evp.h>

int aes256_cbc_encrypt(const uint8_t key[32], const uint8_t iv[16],
                       const uint8_t *pt, size_t pt_len,
                       uint8_t *ct, size_t *ct_len) {
  EVP_CIPHER_CTX *ctx = NULL;
  int outl1 = 0;
  int outl2 = 0;

  if (!key || !iv || !pt || !ct || !ct_len) return -1;
  if ((pt_len % 16U) != 0U) return -1;

  ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return -1;

  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) goto fail;
  if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) goto fail;
  if (EVP_EncryptUpdate(ctx, ct, &outl1, pt, (int)pt_len) != 1) goto fail;
  if (EVP_EncryptFinal_ex(ctx, ct + outl1, &outl2) != 1) goto fail;

  *ct_len = (size_t)(outl1 + outl2);
  EVP_CIPHER_CTX_free(ctx);
  return 0;

fail:
  EVP_CIPHER_CTX_free(ctx);
  return -1;
}

int aes256_cbc_decrypt(const uint8_t key[32], const uint8_t iv[16],
                       const uint8_t *ct, size_t ct_len,
                       uint8_t *pt, size_t *pt_len) {
  EVP_CIPHER_CTX *ctx = NULL;
  int outl1 = 0;
  int outl2 = 0;

  if (!key || !iv || !ct || !pt || !pt_len) return -1;
  if ((ct_len % 16U) != 0U) return -1;

  ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return -1;

  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) goto fail;
  if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) goto fail;
  if (EVP_DecryptUpdate(ctx, pt, &outl1, ct, (int)ct_len) != 1) goto fail;
  if (EVP_DecryptFinal_ex(ctx, pt + outl1, &outl2) != 1) goto fail;

  *pt_len = (size_t)(outl1 + outl2);
  EVP_CIPHER_CTX_free(ctx);
  return 0;

fail:
  EVP_CIPHER_CTX_free(ctx);
  return -1;
}
