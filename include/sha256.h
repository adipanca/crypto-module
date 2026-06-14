#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

void sha256_compute(const uint8_t *in, size_t in_len, uint8_t out[32]);

#endif
