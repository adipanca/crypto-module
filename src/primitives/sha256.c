#include "sha256.h"
#include <openssl/sha.h>

void sha256_compute(const uint8_t *in, size_t in_len, uint8_t out[32]) {
  SHA256(in, in_len, out);
}
