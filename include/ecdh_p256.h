#ifndef ECDH_P256_H
#define ECDH_P256_H

#include <stdint.h>

int ecdh_p256_keygen(uint8_t priv[32], uint8_t pub[65]);
int ecdh_p256_shared(const uint8_t priv[32], const uint8_t peer_pub[65], uint8_t shared[32]);

#endif
