#ifndef CM_SECURE_MEM_H
#define CM_SECURE_MEM_H

#include <stddef.h>

/*
 * secure_zero menghapus isi buffer sensitif secara aman.
 * Menggunakan pointer volatile agar tidak dioptimasi/dihapus oleh compiler.
 * Dipakai untuk zeroization key material (AES key, HMAC key, DRBG state,
 * ECDH private key, dan ML-KEM secret key) saat shutdown / error / selesai sesi.
 */
void secure_zero(void *ptr, size_t len);

#endif
