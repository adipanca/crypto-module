#include "cm_api.h"
#include "mlkem.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdio.h>

static void print_hex(const char *label, const uint8_t *buf, size_t len) {
  printf("%s", label);
  for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
  printf("\n");
}

static void print_hex_trunc(const char *label, const uint8_t *buf, size_t len) {
  size_t show = len < 16 ? len : 16;
  printf("%s", label);
  for (size_t i = 0; i < show; i++) printf("%02x", buf[i]);
  if (len > show) printf("...(%zu byte)", len);
  printf("\n");
}

/* Uji nyata ML-KEM-768: keygen -> encaps -> decaps -> assert ss_encaps == ss_decaps. */
static int test_mlkem_roundtrip(void) {
  uint8_t pk[MLKEM768_PUB_LEN];
  uint8_t sk[MLKEM768_PRIV_LEN];
  uint8_t ct[MLKEM768_CT_LEN];
  uint8_t ss_enc[MLKEM768_SS_LEN];
  uint8_t ss_dec[MLKEM768_SS_LEN];
  size_t pk_len = sizeof(pk);
  size_t sk_len = sizeof(sk);
  size_t ct_len = sizeof(ct);
  size_t ss_enc_len = sizeof(ss_enc);
  size_t ss_dec_len = sizeof(ss_dec);
  int rc;

  printf("ML-KEM-768 KeyGen/Encaps/Decaps Roundtrip\n");

  if (!mlkem_available()) {
    printf("Input: ML-KEM-768 keygen/encaps/decaps\n");
    printf("Expected Output: pk/sk/ct/ss valid dan ss_encaps == ss_decaps\n");
    printf("Result Output: ML-KEM-768 tidak tersedia di provider OpenSSL ini\n");
    printf("[SKIP] ML-KEM-768 not available\n");
    return 0;
  }

  rc = mlkem_keygen(pk, &pk_len, sk, &sk_len);
  if (rc != 0) {
    printf("[FAIL] mlkem_keygen rc=%d\n", rc);
    return 1;
  }

  rc = mlkem_encaps(pk, pk_len, ct, &ct_len, ss_enc, &ss_enc_len);
  if (rc != 0) {
    printf("[FAIL] mlkem_encaps rc=%d\n", rc);
    return 1;
  }

  rc = mlkem_decaps(sk, sk_len, ct, ct_len, ss_dec, &ss_dec_len);
  if (rc != 0) {
    printf("[FAIL] mlkem_decaps rc=%d\n", rc);
    return 1;
  }

  printf("Input: pk(%zu B), sk(%zu B), ct(%zu B)\n", pk_len, sk_len, ct_len);
  print_hex_trunc("  pk = ", pk, pk_len);
  print_hex_trunc("  sk = ", sk, sk_len);
  print_hex_trunc("  ct = ", ct, ct_len);
  printf("Expected Output: ss_encaps == ss_decaps (32 byte identik)\n");
  print_hex("  ss_encaps (Result) = ", ss_enc, ss_enc_len);
  print_hex("  ss_decaps (Result) = ", ss_dec, ss_dec_len);

  if (ss_enc_len != MLKEM768_SS_LEN || ss_dec_len != MLKEM768_SS_LEN) {
    printf("[FAIL] panjang shared secret tidak sesuai\n");
    return 1;
  }
  if (memcmp(ss_enc, ss_dec, MLKEM768_SS_LEN) != 0) {
    printf("[FAIL] shared secret encaps != decaps\n");
    return 1;
  }

  printf("[PASS] ML-KEM-768 roundtrip (ss_encaps == ss_decaps)\n");
  return 0;
}

static int test_hybrid_formula(void) {
  uint8_t ecdh_secret[32];
  uint8_t mlkem_secret[32];
  uint8_t got[32];
  uint8_t expected[32];
  uint8_t concat[64];

  for (size_t i = 0; i < 32; i++) {
    ecdh_secret[i] = (uint8_t)i;
    mlkem_secret[i] = (uint8_t)(0xA0U + i);
  }

  memcpy(concat, ecdh_secret, 32);
  memcpy(concat + 32, mlkem_secret, 32);
  SHA256(concat, sizeof(concat), expected);

  if (cm_hybrid_derive_shared(ecdh_secret, mlkem_secret, sizeof(mlkem_secret), got) != CM_OK) {
    printf("[FAIL] cm_hybrid_derive_shared returned error\n");
    return 1;
  }
  printf("Hybrid Derivation Test\n");
  printf("Input: ECDH secret (00..1f) + MLKEM secret (a0..bf)\n");
  print_hex("Expected Output: ", expected, sizeof(expected));
  print_hex("Result Output: ", got, sizeof(got));
  if (memcmp(got, expected, 32) != 0) {
    printf("[FAIL] hybrid formula mismatch\n");
    return 1;
  }

  printf("[PASS] hybrid formula SHA256(ECDH||MLKEM)\n");
  return 0;
}

static int test_hybrid_api_flow(void) {
  uint8_t priv_a[32], pub_a[65];
  uint8_t priv_b[32], pub_b[65];
  uint8_t mlkem_secret[32];
  uint8_t out_a[32], out_b[32];

  for (size_t i = 0; i < 32; i++) mlkem_secret[i] = (uint8_t)(0x55U + i);

  if (cm_module_init() != CM_OK) {
    printf("[FAIL] cm_module_init\n");
    return 1;
  }
  if (cm_ecdh_p256_keygen(priv_a, pub_a) != CM_OK || cm_ecdh_p256_keygen(priv_b, pub_b) != CM_OK) {
    cm_module_shutdown();
    printf("[FAIL] ecdh keygen\n");
    return 1;
  }

  if (cm_hybrid_ecdh_mlkem_shared(priv_a, pub_b, mlkem_secret, sizeof(mlkem_secret), out_a) != CM_OK ||
      cm_hybrid_ecdh_mlkem_shared(priv_b, pub_a, mlkem_secret, sizeof(mlkem_secret), out_b) != CM_OK) {
    cm_module_shutdown();
    printf("[FAIL] hybrid api flow\n");
    return 1;
  }

  cm_module_shutdown();

  if (memcmp(out_a, out_b, 32) != 0) {
    printf("[FAIL] hybrid shared mismatch between peers\n");
    return 1;
  }
  printf("\nHybrid API Flow Test\n");
  printf("Input: (privA,pubB,mlkem_secret) dan (privB,pubA,mlkem_secret)\n");
  print_hex("Expected Output: ", out_a, sizeof(out_a));
  print_hex("Result Output: ", out_b, sizeof(out_b));
  printf("[PASS] hybrid API flow\n");
  return 0;
}

int main(void) {
  int fail = 0;

  fail |= test_mlkem_roundtrip();
  fail |= test_hybrid_formula();
  fail |= test_hybrid_api_flow();

  printf("\nML-KEM Provider Availability\n");
  printf("Input: query EVP_PKEY_CTX_new_from_name(ML-KEM-768)\n");
  printf("Expected Output: context tersedia (non-NULL)\n");
  printf("Result Output: %s\n", mlkem_available() ? "available" : "not available");
  if (mlkem_available()) {
    printf("[PASS] ML-KEM-768 algorithm is available in OpenSSL provider\n");
  } else {
    printf("[SKIP] ML-KEM-768 not available in current OpenSSL provider/build\n");
  }

  return fail ? 1 : 0;
}
