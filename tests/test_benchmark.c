#include "cm_api.h"

#include <openssl/evp.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BENCH_CSV_PATH "docs/benchmark_results.csv"

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif

typedef struct {
  const char *name;
  size_t iterations;
  double total_ms;
  double avg_us;
  double ops_per_sec;
  const char *status;
} bench_result_t;

static uint64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void finalize_result(bench_result_t *r, uint64_t elapsed_ns) {
  r->total_ms = (double)elapsed_ns / 1e6;
  r->avg_us = r->iterations ? ((double)elapsed_ns / (double)r->iterations) / 1e3 : 0.0;
  r->ops_per_sec = elapsed_ns ? ((double)r->iterations * 1e9) / (double)elapsed_ns : 0.0;
}

static int bench_ecc_keygen(bench_result_t *r, size_t iterations) {
  uint8_t priv[32], pub[65];
  r->name = "ecc_keygen_p256";
  r->iterations = iterations;
  r->status = "PASS";

  uint64_t t0 = now_ns();
  for (size_t i = 0; i < iterations; i++) {
    if (cm_ecdh_p256_keygen(priv, pub) != CM_OK) {
      r->status = "FAIL";
      r->iterations = i;
      finalize_result(r, now_ns() - t0);
      return 1;
    }
  }
  finalize_result(r, now_ns() - t0);
  return 0;
}

static int bench_ecc_multiplication(bench_result_t *r, size_t iterations) {
  uint8_t priv_a[32], pub_a[65];
  uint8_t priv_b[32], pub_b[65];
  uint8_t shared[32];

  r->name = "ecc_scalar_mul_p256";
  r->iterations = iterations;
  r->status = "PASS";

  if (cm_ecdh_p256_keygen(priv_a, pub_a) != CM_OK || cm_ecdh_p256_keygen(priv_b, pub_b) != CM_OK) {
    r->status = "FAIL";
    r->iterations = 0;
    r->total_ms = 0.0;
    r->avg_us = 0.0;
    r->ops_per_sec = 0.0;
    return 1;
  }

  uint64_t t0 = now_ns();
  for (size_t i = 0; i < iterations; i++) {
    if (cm_ecdh_p256_shared(priv_a, pub_b, shared) != CM_OK) {
      r->status = "FAIL";
      r->iterations = i;
      finalize_result(r, now_ns() - t0);
      return 1;
    }
  }
  finalize_result(r, now_ns() - t0);
  return 0;
}

static int bench_kem_keygen(bench_result_t *r, size_t iterations) {
  EVP_PKEY_CTX *ctx = NULL;
  EVP_PKEY *key = NULL;

  r->name = "kem_keygen_mlkem768";
  r->iterations = iterations;

#if OPENSSL_VERSION_MAJOR < 3
  r->status = "SKIP";
  r->iterations = 0;
  r->total_ms = 0.0;
  r->avg_us = 0.0;
  r->ops_per_sec = 0.0;
  return 0;
#else
  ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
  if (!ctx) {
    r->status = "SKIP";
    r->iterations = 0;
    r->total_ms = 0.0;
    r->avg_us = 0.0;
    r->ops_per_sec = 0.0;
    return 0;
  }

  r->status = "PASS";
  uint64_t t0 = now_ns();
  for (size_t i = 0; i < iterations; i++) {
    EVP_PKEY_free(key);
    key = NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_generate(ctx, &key) <= 0 || !key) {
      r->status = "FAIL";
      r->iterations = i;
      finalize_result(r, now_ns() - t0);
      EVP_PKEY_free(key);
      EVP_PKEY_CTX_free(ctx);
      return 1;
    }
  }
  finalize_result(r, now_ns() - t0);

  EVP_PKEY_free(key);
  EVP_PKEY_CTX_free(ctx);
  return 0;
#endif
}

static int bench_kem_enc_dec(bench_result_t *enc, bench_result_t *dec, size_t iterations) {
#if OPENSSL_VERSION_MAJOR < 3
  enc->name = "kem_encaps_mlkem768";
  enc->iterations = 0;
  enc->total_ms = 0.0;
  enc->avg_us = 0.0;
  enc->ops_per_sec = 0.0;
  enc->status = "SKIP";

  dec->name = "kem_decaps_mlkem768";
  dec->iterations = 0;
  dec->total_ms = 0.0;
  dec->avg_us = 0.0;
  dec->ops_per_sec = 0.0;
  dec->status = "SKIP";
  return 0;
#else
  EVP_PKEY_CTX *kgctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
  EVP_PKEY *key = NULL;
  EVP_PKEY_CTX *ectx = NULL;
  EVP_PKEY_CTX *dctx = NULL;

  enc->name = "kem_encaps_mlkem768";
  enc->iterations = iterations;
  enc->status = "PASS";

  dec->name = "kem_decaps_mlkem768";
  dec->iterations = iterations;
  dec->status = "PASS";

  if (!kgctx || EVP_PKEY_keygen_init(kgctx) <= 0 || EVP_PKEY_generate(kgctx, &key) <= 0 || !key) {
    enc->iterations = 0;
    enc->total_ms = enc->avg_us = enc->ops_per_sec = 0.0;
    enc->status = "SKIP";

    dec->iterations = 0;
    dec->total_ms = dec->avg_us = dec->ops_per_sec = 0.0;
    dec->status = "SKIP";

    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(kgctx);
    return 0;
  }

  ectx = EVP_PKEY_CTX_new(key, NULL);
  dctx = EVP_PKEY_CTX_new(key, NULL);
  if (!ectx || !dctx) {
    enc->status = "FAIL";
    dec->status = "FAIL";
    enc->iterations = 0;
    dec->iterations = 0;
    enc->total_ms = enc->avg_us = enc->ops_per_sec = 0.0;
    dec->total_ms = dec->avg_us = dec->ops_per_sec = 0.0;
    EVP_PKEY_CTX_free(ectx);
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(kgctx);
    return 1;
  }

  if (EVP_PKEY_encapsulate_init(ectx, NULL) <= 0 || EVP_PKEY_decapsulate_init(dctx, NULL) <= 0) {
    enc->status = "SKIP";
    dec->status = "SKIP";
    enc->iterations = 0;
    dec->iterations = 0;
    enc->total_ms = enc->avg_us = enc->ops_per_sec = 0.0;
    dec->total_ms = dec->avg_us = dec->ops_per_sec = 0.0;
    EVP_PKEY_CTX_free(ectx);
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(kgctx);
    return 0;
  }

  size_t ct_len = 0;
  size_t ss_len = 0;
  if (EVP_PKEY_encapsulate(ectx, NULL, &ct_len, NULL, &ss_len) <= 0 || ct_len == 0 || ss_len == 0) {
    enc->status = "SKIP";
    dec->status = "SKIP";
    enc->iterations = 0;
    dec->iterations = 0;
    enc->total_ms = enc->avg_us = enc->ops_per_sec = 0.0;
    dec->total_ms = dec->avg_us = dec->ops_per_sec = 0.0;
    EVP_PKEY_CTX_free(ectx);
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(kgctx);
    return 0;
  }

  uint8_t *ct = (uint8_t *)malloc(ct_len);
  uint8_t *ss_enc = (uint8_t *)malloc(ss_len);
  uint8_t *ss_dec = (uint8_t *)malloc(ss_len);
  if (!ct || !ss_enc || !ss_dec) {
    enc->status = "FAIL";
    dec->status = "FAIL";
    enc->iterations = 0;
    dec->iterations = 0;
    enc->total_ms = enc->avg_us = enc->ops_per_sec = 0.0;
    dec->total_ms = dec->avg_us = dec->ops_per_sec = 0.0;
    free(ct);
    free(ss_enc);
    free(ss_dec);
    EVP_PKEY_CTX_free(ectx);
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(kgctx);
    return 1;
  }

  uint64_t t_enc0 = now_ns();
  for (size_t i = 0; i < iterations; i++) {
    size_t ct_i = ct_len;
    size_t ss_i = ss_len;
    if (EVP_PKEY_encapsulate(ectx, ct, &ct_i, ss_enc, &ss_i) <= 0) {
      enc->status = "FAIL";
      enc->iterations = i;
      finalize_result(enc, now_ns() - t_enc0);
      dec->status = "SKIP";
      dec->iterations = 0;
      dec->total_ms = dec->avg_us = dec->ops_per_sec = 0.0;
      free(ct);
      free(ss_enc);
      free(ss_dec);
      EVP_PKEY_CTX_free(ectx);
      EVP_PKEY_CTX_free(dctx);
      EVP_PKEY_free(key);
      EVP_PKEY_CTX_free(kgctx);
      return 1;
    }
  }
  finalize_result(enc, now_ns() - t_enc0);

  size_t ct_i = ct_len;
  size_t ss_i = ss_len;
  if (EVP_PKEY_encapsulate(ectx, ct, &ct_i, ss_enc, &ss_i) <= 0) {
    dec->status = "FAIL";
    dec->iterations = 0;
    dec->total_ms = dec->avg_us = dec->ops_per_sec = 0.0;
    free(ct);
    free(ss_enc);
    free(ss_dec);
    EVP_PKEY_CTX_free(ectx);
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(kgctx);
    return 1;
  }

  uint64_t t_dec0 = now_ns();
  for (size_t i = 0; i < iterations; i++) {
    size_t out_i = ss_len;
    if (EVP_PKEY_decapsulate(dctx, ss_dec, &out_i, ct, ct_i) <= 0) {
      dec->status = "FAIL";
      dec->iterations = i;
      finalize_result(dec, now_ns() - t_dec0);
      free(ct);
      free(ss_enc);
      free(ss_dec);
      EVP_PKEY_CTX_free(ectx);
      EVP_PKEY_CTX_free(dctx);
      EVP_PKEY_free(key);
      EVP_PKEY_CTX_free(kgctx);
      return 1;
    }
  }
  finalize_result(dec, now_ns() - t_dec0);

  free(ct);
  free(ss_enc);
  free(ss_dec);
  EVP_PKEY_CTX_free(ectx);
  EVP_PKEY_CTX_free(dctx);
  EVP_PKEY_free(key);
  EVP_PKEY_CTX_free(kgctx);
  return 0;
#endif
}

static void print_result(const bench_result_t *r) {
  printf("%-24s | iter=%-6zu | total=%8.3f ms | avg=%8.3f us/op | throughput=%10.2f op/s | %s\n",
         r->name, r->iterations, r->total_ms, r->avg_us, r->ops_per_sec, r->status);
}

static int write_csv(const bench_result_t *rows, size_t n) {
  FILE *fp = fopen(BENCH_CSV_PATH, "w");
  if (!fp) {
    perror("fopen");
    return 1;
  }

  fprintf(fp, "operation,iterations,total_ms,avg_us,ops_per_sec,status\n");
  for (size_t i = 0; i < n; i++) {
    fprintf(fp, "%s,%zu,%.6f,%.6f,%.6f,%s\n",
            rows[i].name,
            rows[i].iterations,
            rows[i].total_ms,
            rows[i].avg_us,
            rows[i].ops_per_sec,
            rows[i].status);
  }

  fclose(fp);
  return 0;
}

int main(void) {
  const size_t ecc_iter = 2000;
  const size_t kem_iter = 500;

  bench_result_t results[5];
  memset(results, 0, sizeof(results));

  if (cm_module_init() != CM_OK) {
    printf("[FAIL] cm_module_init gagal, benchmark tidak bisa dijalankan\n");
    return 1;
  }

  int fail = 0;
  fail |= bench_ecc_keygen(&results[0], ecc_iter);
  fail |= bench_ecc_multiplication(&results[1], ecc_iter);

  if (cm_module_shutdown() != CM_OK) {
    printf("[WARN] cm_module_shutdown mengembalikan error\n");
  }

  fail |= bench_kem_keygen(&results[2], kem_iter);
  fail |= bench_kem_enc_dec(&results[3], &results[4], kem_iter);

  printf("\nBenchmark ECC/KEM (OpenSSL backend)\n");
  printf("Output CSV: %s\n\n", BENCH_CSV_PATH);
  for (size_t i = 0; i < 5; i++) {
    print_result(&results[i]);
  }

  if (write_csv(results, 5) != 0) {
    printf("[FAIL] gagal menulis CSV benchmark\n");
    return 1;
  }

  if (fail) {
    printf("\n[FAIL] benchmark selesai dengan error parsial\n");
    return 1;
  }

  printf("\n[PASS] benchmark selesai\n");
  return 0;
}
