#ifndef AES256_H
#define AES256_H

#include <stddef.h>
#include <stdint.h>

int aes256_cbc_encrypt(const uint8_t key[32], const uint8_t iv[16],
                       const uint8_t *pt, size_t pt_len,
                       uint8_t *ct, size_t *ct_len);

int aes256_cbc_decrypt(const uint8_t key[32], const uint8_t iv[16],
                       const uint8_t *ct, size_t ct_len,
                       uint8_t *pt, size_t *pt_len);

#endif
