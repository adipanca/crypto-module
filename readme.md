# Crypto Module (C)

An cryptographic module skeleton implemented in C using OpenSSL as the cryptographic backend.

## Features

### Cryptographic Primitives

- AES-256-CBC (EVP)
- SHA-256
- HMAC-SHA256
- ECDH P-256
- CTR-based DRBG Skeleton (AES-256-CTR EVP)

### Hybrid Key Derivation

The module provides built-in support for hybrid shared secret derivation through:

```c
cm_hybrid_derive_shared(
    ecdh_secret,
    mlkem_secret,
    mlkem_len,
    out32
);

cm_hybrid_ecdh_mlkem_shared(
    priv,
    peer_pub,
    mlkem_secret,
    mlkem_len,
    out32
);
```

Hybrid shared secret formula:

```text
Shared Secret = SHA256(ECDH_secret || MLKEM_secret)
```

### Runtime Integrity Verification

At runtime, the module computes the SHA-256 hash of the currently running executable and compares it against a sidecar hash file:

```text
<binary>.sha256
```

---

# Prerequisites

Install the following dependencies:

- GCC or Clang
- OpenSSL development package
- pkg-config
- make

Verify OpenSSL installation:

```bash
pkg-config --modversion openssl
```

---

# Build

From the project root directory:

```bash
make clean
make
```

The build process automatically generates:

- Test binaries in `build/`
- Sidecar integrity hashes

Example:

```text
build/test_main
build/test_main.sha256
```

---

# Running Tests

## Run All Tests

```bash
make test-all
```

## Run Main Test

```bash
make test
```

---

# Test Categories

## FSM Test

```bash
make test-fsm
```

Verifies:

- Cryptographic operations are rejected before initialization.
- Cryptographic operations are accepted after successful initialization.

---

## SELF-TEST (POST)

```bash
make test-selftest
```

Verifies:

- Integrity check
- Known Answer Test (KAT) suite
- Conditional test hooks

---

## Known Answer Tests (KAT)

```bash
make test-kat
```

Verifies:

- AES-256 KAT
- SHA-256 KAT
- HMAC-SHA256 KAT
- CTR-DRBG KAT
- ECDH P-256 KAT

---

## Integrity Test

```bash
make test-integrity
```

Verifies:

- Runtime executable path detection
- SHA-256 hashing of the executable
- Sidecar hash verification
- Tamper detection by modifying the sidecar hash file
- Successful recovery after restoration

---

## Entropy Test

```bash
make test-entropy
```

Verifies:

- Normal entropy stream validation
- Repetition Count Test (RCT)
- Adaptive Proportion Test (APT)
- Entropy update logic through `cm_entropy_update`

---

## ML-KEM Test

```bash
make test-mlkem
```

Performs:

1. ML-KEM-768 key generation
2. Encapsulation
3. Decapsulation
4. Shared secret verification

```text
ss_encaps == ss_decaps
```

Also verifies hybrid derivation:

```text
SHA256(ECDH || ML-KEM)
```

Results:

| Status | Description |
|----------|-------------|
| PASS | ML-KEM-768 available in OpenSSL provider |
| SKIP | OpenSSL build does not provide ML-KEM support |

---

# Negative Tests

```bash
make test-negative
```

Fault injection variables:

```bash
CM_FORCE_KAT_FAIL=1
CM_FORCE_ENTROPY_FAIL=1
CM_FORCE_INTEGRITY_FAIL=1
```

Each condition must drive the module into the expected error state.

---

# Binary Integrity Notes

If the executable changes, its corresponding sidecar hash must be regenerated.

The easiest way is to rebuild:

```bash
make clean && make
```

---

# Available Make Targets

## Testing

```bash
make test
make test-fsm
make test-selftest
make test-kat
make test-integrity
make test-entropy
make test-negative
make test-mlkem
make test-assessment
make test-bench
make test-all
```

## Coverage

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

---

# ECC and KEM Benchmark

Run performance benchmarks:

```bash
make test-bench
```

The benchmark measures:

- ECC P-256 key generation
- ECC P-256 ECDH shared secret generation
- ML-KEM-768 key generation
- ML-KEM-768 encapsulation
- ML-KEM-768 decapsulation

Results are exported to:

```text
docs/benchmark_results.csv
```

## CSV Columns

| Column | Description |
|----------|-------------|
| operation | Benchmark operation |
| iterations | Number of iterations |
| total_ms | Total execution time (ms) |
| avg_us | Average execution time (µs) |
| ops_per_sec | Operations per second |
| status | Benchmark status |

---

# Coverage Reports

Coverage summaries are generated in:

```text
coverage/*.txt
```

Example:

```text
coverage/main.txt
coverage/fsm.txt
coverage/kat.txt
coverage/integrity.txt
```

## Notes

- Coverage reports are intended for educational, debugging, and evaluation purposes.
- If `gcov` is not installed, coverage files may be empty.

---

# Project Goal

This project serves as a lightweight cryptographic module framework for security research, supporting:

- Classical cryptography
- Post-quantum cryptography experimentation
- Hybrid ECDH + ML-KEM key establishment
- Integrity verification
- Entropy source validation
- Security assessment and benchmarking