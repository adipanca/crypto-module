#include "cm_integrity.h"
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#elif defined(__linux__)
#include <unistd.h>
#endif

static int get_executable_path(char *buf, size_t buf_size) {
#if defined(__APPLE__)
  uint32_t size = (uint32_t)buf_size;
  if (_NSGetExecutablePath(buf, &size) != 0) return -1;
  return 0;
#elif defined(__linux__)
  ssize_t n = readlink("/proc/self/exe", buf, buf_size - 1);
  if (n <= 0) return -1;
  buf[n] = '\0';
  return 0;
#else
  (void)buf;
  (void)buf_size;
  return -1;
#endif
}

static int sha256_file(const char *path, uint8_t out[32]) {
  FILE *fp = NULL;
  EVP_MD_CTX *ctx = NULL;
  uint8_t block[4096];
  unsigned int out_len = 0;
  size_t n;

  fp = fopen(path, "rb");
  if (!fp) return -1;

  ctx = EVP_MD_CTX_new();
  if (!ctx) {
    fclose(fp);
    return -1;
  }

  if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
    EVP_MD_CTX_free(ctx);
    fclose(fp);
    return -1;
  }

  while ((n = fread(block, 1, sizeof(block), fp)) > 0) {
    if (EVP_DigestUpdate(ctx, block, n) != 1) {
      EVP_MD_CTX_free(ctx);
      fclose(fp);
      return -1;
    }
  }

  if (ferror(fp)) {
    EVP_MD_CTX_free(ctx);
    fclose(fp);
    return -1;
  }

  fclose(fp);
  if (EVP_DigestFinal_ex(ctx, out, &out_len) != 1) {
    EVP_MD_CTX_free(ctx);
    return -1;
  }
  EVP_MD_CTX_free(ctx);
  if (out_len != 32U) return -1;
  return 0;
}

static int hex_to_bytes(const char *hex, uint8_t out[32]) {
  for (size_t i = 0; i < 32; i++) {
    unsigned int v;
    if (sscanf(hex + (2 * i), "%2x", &v) != 1) return -1;
    out[i] = (uint8_t)v;
  }
  return 0;
}

cm_status_t cm_run_integrity_check(void) {
  char exe_path[PATH_MAX];
  char hash_path[PATH_MAX + 8];
  char expected_hex[65] = {0};
  uint8_t expected[32];
  uint8_t actual[32];
  FILE *fp = NULL;

  if (getenv("CM_FORCE_INTEGRITY_FAIL")) return CM_ERR_INTEGRITY;

  if (get_executable_path(exe_path, sizeof(exe_path)) != 0) return CM_ERR_INTEGRITY;
  if (snprintf(hash_path, sizeof(hash_path), "%s.sha256", exe_path) <= 0) return CM_ERR_INTEGRITY;

  fp = fopen(hash_path, "r");
  if (!fp) return CM_ERR_INTEGRITY;
  if (fscanf(fp, "%64s", expected_hex) != 1) {
    fclose(fp);
    return CM_ERR_INTEGRITY;
  }
  fclose(fp);

  if (hex_to_bytes(expected_hex, expected) != 0) return CM_ERR_INTEGRITY;
  if (sha256_file(exe_path, actual) != 0) return CM_ERR_INTEGRITY;
  if (CRYPTO_memcmp(expected, actual, sizeof(expected)) != 0) return CM_ERR_INTEGRITY;

  return CM_OK;
}
