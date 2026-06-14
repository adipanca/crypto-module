# Crypto Module (C) - Build and Test Guide

Proyek ini adalah skeleton modul kriptografi IoT yang memakai backend OpenSSL untuk primitive utama:
- AES-256-CBC (EVP)
- SHA-256
- HMAC-SHA256
- ECDH P-256
- CTR-based DRBG skeleton (berbasis AES-256-CTR EVP)

Integrasi hybrid key derivation sudah tersedia di API inti:
- `cm_hybrid_derive_shared(ecdh_secret, mlkem_secret, mlkem_len, out32)`
- `cm_hybrid_ecdh_mlkem_shared(priv, peer_pub, mlkem_secret, mlkem_len, out32)`

Rumus hybrid:

```text
Shared Secret = SHA256(ECDH_secret || MLKEM_secret)
```

Integrity check runtime aktif: binary yang sedang berjalan di-hash SHA-256 dan dibandingkan dengan file sidecar hash `<binary>.sha256`.

## 1) Prasyarat

- C compiler (gcc/clang)
- OpenSSL development package (headers + libcrypto)
- `pkg-config`
- `make`

Contoh cek cepat:

```bash
pkg-config --modversion openssl
```

## 2) Build

Dari folder `crypto-module`:

```bash
make clean
make
```

Build ini otomatis membuat:
- binary test di folder `build/`
- file hash sidecar untuk setiap binary: `build/<nama_test>.sha256`

## 3) Menjalankan Semua Test

```bash
make test-all
```

## 4) Menjalankan Test Per Kategori

### a. FSM

```bash
make test-fsm
```

Yang dicek:
- Operasi kripto ditolak sebelum `cm_module_init`
- Operasi kripto diterima setelah inisialisasi sukses

### b. SELF TEST (POST)

```bash
make test-selftest
```

Yang dicek:
- Integrity check
- KAT suite
- Conditional test hook

### c. KAT

```bash
make test-kat
```

Yang dicek:
- KAT AES-256
- KAT SHA-256
- KAT HMAC-SHA256
- KAT CTR-DRBG
- KAT ECDH P-256

### d. Integrity Test

```bash
make test-integrity
```

Yang dicek:
- Runtime membaca path binary aktif
- Runtime hitung SHA-256 binary
- Runtime bandingkan dengan sidecar hash `<binary>.sha256`
- Tamper test nyata: file sidecar hash diubah sementara, verifikasi harus gagal, lalu file dipulihkan dan verifikasi harus kembali lolos

### e. Entropy Test

```bash
make test-entropy
```

Yang dicek:
- Entropy stream normal harus lolos
- RCT threshold harus terpicu pada pola repetitif
- APT logic dijalankan melalui `cm_entropy_update`

### f. ML-KEM Test

```bash
make test-mlkem
```

Perilaku:
- Menjalankan ML-KEM-768 **keygen → encaps → decaps** nyata dan memverifikasi `ss_encaps == ss_decaps`
- Menguji hybrid derivation `SHA256(ECDH || MLKEM)`
- `PASS` jika algoritma `ML-KEM-768` tersedia di provider OpenSSL Anda
- `SKIP` pada bagian roundtrip jika provider/build OpenSSL belum menyediakan ML-KEM

## 5) Negative Test

```bash
make test-negative
```

Negative test memakai fault injection environment variable:
- `CM_FORCE_KAT_FAIL=1`
- `CM_FORCE_ENTROPY_FAIL=1`
- `CM_FORCE_INTEGRITY_FAIL=1`

Masing-masing harus mendorong modul ke kondisi error yang benar.

## 6) Menjalankan Test Utama Sederhana

```bash
make test
```

## 7) Catatan Integritas Binary

Karena integrity check membandingkan hash binary aktif, jika binary berubah maka hash sidecar harus di-regenerate. Cara termudah: build ulang.

```bash
make clean && make
```

## 8) Struktur Target Make

- `make test`
- `make test-fsm`
- `make test-selftest`
- `make test-kat`
- `make test-integrity`
- `make test-entropy`
- `make test-negative`
- `make test-mlkem`
- `make test-assessment`
- `make test-bench`
- `make test-all`

## 9) Benchmark ECC dan KEM

Jalankan benchmark performa operasi inti ECC dan KEM:

```bash
make test-bench
```

Benchmark ini mengeksekusi:
- ECC P-256 key generation
- ECC P-256 scalar multiplication (ECDH shared)
- ML-KEM-768 key generation
- ML-KEM-768 encapsulation
- ML-KEM-768 decapsulation

Output CSV akan ditulis ke:

```text
docs/benchmark_results.csv
```

Kolom CSV:
- `operation`
- `iterations`
- `total_ms`
- `avg_us`
- `ops_per_sec`
- `status`

## 10) Coverage Report Sederhana (Per Target)

Target coverage tersedia per jenis test dan menghasilkan ringkasan gcov di `coverage/*.txt`.

```bash
make coverage-main
make coverage-fsm
make coverage-selftest
make coverage-kat
make coverage-integrity
make coverage-entropy
make coverage-negative
make coverage-mlkem
make coverage-assessment
make coverage-all
```

Catatan:
- Coverage ini bersifat ringkas untuk kebutuhan praktikum dan debugging.
- Jika `gcov` tidak tersedia di sistem, file report bisa kosong.
