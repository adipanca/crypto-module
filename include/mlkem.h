#ifndef MLKEM_H
#define MLKEM_H

#include <stddef.h>
#include <stdint.h>

/*
 * Implementasi ML-KEM-768 (FIPS 203) di atas backend OpenSSL provider.
 * Modul ini mengekspos tiga operasi inti KEM:
 *   - mlkem_keygen  : menghasilkan pasangan (encapsulation key / pk,
 *                     decapsulation key / sk)
 *   - mlkem_encaps  : encapsulation menggunakan pk -> (ciphertext, shared secret)
 *   - mlkem_decaps  : decapsulation menggunakan sk + ciphertext -> shared secret
 *
 * Kontrak ukuran ML-KEM-768:
 *   pk  (encapsulation key) = 1184 byte
 *   sk  (decapsulation key) = 2400 byte
 *   ct  (ciphertext)        = 1088 byte
 *   ss  (shared secret)     = 32 byte
 *
 * Return value:
 *    0  = sukses
 *   -1  = error operasi kripto
 *    1  = ML-KEM tidak tersedia pada build/provider OpenSSL saat ini (SKIP)
 */

#define MLKEM768_PUB_LEN 1184
#define MLKEM768_PRIV_LEN 2400
#define MLKEM768_CT_LEN 1088
#define MLKEM768_SS_LEN 32

int mlkem_available(void);

int mlkem_keygen(uint8_t *pk, size_t *pk_len, uint8_t *sk, size_t *sk_len);

int mlkem_encaps(const uint8_t *pk, size_t pk_len,
                 uint8_t *ct, size_t *ct_len,
                 uint8_t *ss, size_t *ss_len);

int mlkem_decaps(const uint8_t *sk, size_t sk_len,
                 const uint8_t *ct, size_t ct_len,
                 uint8_t *ss, size_t *ss_len);

#endif
