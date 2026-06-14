#include "cm_api.h"
#include "cm_error.h"
#include "cm_selftest.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

static int g_fail = 0;

static void print_check(const char *name, int pass) {
  if (pass) {
    printf("[PASS] %s\n", name);
  } else {
    printf("[FAIL] %s\n", name);
    g_fail = 1;
  }
}

static void test_algorithms(void) {
  uint8_t key[32], iv[16], pt[16], ct[32], rt[32];
  uint8_t hash[32], mac[32], rnd[16];
  uint8_t priv_a[32], pub_a[65], priv_b[32], pub_b[65], sec_ab[32], sec_ba[32];
  size_t ct_len = 0, rt_len = 0;

  for (size_t i = 0; i < sizeof(key); i++) key[i] = (uint8_t)(0x10U + i);
  for (size_t i = 0; i < sizeof(iv); i++) iv[i] = (uint8_t)i;
  for (size_t i = 0; i < sizeof(pt); i++) pt[i] = (uint8_t)(0xA0U + i);

  print_check("Algoritma simetris (AES-256-CBC)",
              cm_encrypt_aes256_cbc(key, iv, pt, sizeof(pt), ct, &ct_len) == CM_OK &&
              cm_decrypt_aes256_cbc(key, iv, ct, ct_len, rt, &rt_len) == CM_OK &&
              rt_len == sizeof(pt) && memcmp(pt, rt, sizeof(pt)) == 0);

  print_check("Fungsi hash (SHA-256)",
              cm_sha256((const uint8_t *)"abc", 3, hash) == CM_OK);

  print_check("RNG (CTR-DRBG generate)",
              cm_drbg_generate(rnd, sizeof(rnd)) == CM_OK);

  print_check("MAC (HMAC-SHA256)",
              cm_hmac_sha256(key, sizeof(key), pt, sizeof(pt), mac) == CM_OK);

  print_check("ECC (ECDH P-256)",
              cm_ecdh_p256_keygen(priv_a, pub_a) == CM_OK &&
              cm_ecdh_p256_keygen(priv_b, pub_b) == CM_OK &&
              cm_ecdh_p256_shared(priv_a, pub_b, sec_ab) == CM_OK &&
              cm_ecdh_p256_shared(priv_b, pub_a, sec_ba) == CM_OK &&
              memcmp(sec_ab, sec_ba, 32) == 0);
}

static void test_runtime_selftests(void) {
  print_check("KAT runtime", cm_run_kat_all() == CM_OK);
  print_check("Integrity runtime", cm_run_integrity_check() == CM_OK);
  print_check("Entropy runtime", cm_run_conditional_test() == CM_OK);
}

static void test_conditional_and_fsm(void) {
  uint8_t out[8];

  cm_module_shutdown();
  print_check("FSM gate before init", cm_drbg_generate(out, sizeof(out)) == CM_ERR_STATE);
  print_check("FSM init to operational", cm_module_init() == CM_OK);
  print_check("FSM gate after init", cm_drbg_generate(out, sizeof(out)) == CM_OK);
}

static void test_mlkem_bonus(void) {
  uint8_t ecdh_secret[32], mlkem_secret[32], hybrid[32];
  EVP_PKEY_CTX *ctx;

  for (size_t i = 0; i < 32; i++) {
    ecdh_secret[i] = (uint8_t)i;
    mlkem_secret[i] = (uint8_t)(0x80U + i);
  }

  print_check("Hybrid derivation SHA256(ECDH||MLKEM)",
              cm_hybrid_derive_shared(ecdh_secret, mlkem_secret, sizeof(mlkem_secret), hybrid) == CM_OK);

#if OPENSSL_VERSION_MAJOR >= 3
  ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
  print_check("Bonus ML-KEM-768 tersedia", ctx != NULL);
  if (ctx) EVP_PKEY_CTX_free(ctx);
#else
  print_check("Bonus ML-KEM-768 tersedia", 0);
#endif
}

int main(void) {
  if (cm_module_init() != CM_OK) {
    printf("[FAIL] cm_module_init awal\n");
    return 1;
  }

  printf("=== Penilaian Kriteria Tugas ===\n");
  test_algorithms();
  test_runtime_selftests();
  test_conditional_and_fsm();
  test_mlkem_bonus();

  cm_module_shutdown();

  if (g_fail) {
    printf("\nRINGKASAN: ADA KRITERIA YANG BELUM PASS\n");
    return 1;
  }

  printf("\nRINGKASAN: SEMUA KRITERIA PASS\n");
  return 0;
}
