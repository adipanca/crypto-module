#include "hmac_sha256.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>

void hmac_sha256_compute(const uint8_t *key, size_t key_len,
                         const uint8_t *msg, size_t msg_len,
                         uint8_t tag[32]) {
  unsigned int out_len = 0;
  HMAC(EVP_sha256(), key, (int)key_len, msg, msg_len, tag, &out_len);
}
