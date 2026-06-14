#include "cm_api.h"
#include "cm_error.h"
#include <limits.h>
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

static int tamper_hash_file(const char *hash_path, const char *original) {
  FILE *fp;
  char tampered[256];

  strncpy(tampered, original, sizeof(tampered) - 1);
  tampered[sizeof(tampered) - 1] = '\0';
  if (tampered[0] == 'a') tampered[0] = 'b';
  else tampered[0] = 'a';

  fp = fopen(hash_path, "w");
  if (!fp) return -1;
  if (fputs(tampered, fp) < 0) {
    fclose(fp);
    return -1;
  }
  fclose(fp);
  return 0;
}

static int restore_hash_file(const char *hash_path, const char *original) {
  FILE *fp = fopen(hash_path, "w");
  if (!fp) return -1;
  if (fputs(original, fp) < 0) {
    fclose(fp);
    return -1;
  }
  fclose(fp);
  return 0;
}

int main(void) {
  char exe_path[PATH_MAX];
  char hash_path[PATH_MAX + 8];
  char original[256] = {0};
  cm_status_t st = cm_run_integrity_check();
  printf("Integrity Check A\nInput: binary aktif + sidecar hash asli\nExpected Output: CM_OK\nResult Output: %s\n", cm_status_str(st));

  if (st != CM_OK) {
    printf("[FAIL] cm_run_integrity_check: %s\n", cm_status_str(st));
    return 1;
  }

  if (get_executable_path(exe_path, sizeof(exe_path)) != 0) {
    printf("[FAIL] cannot resolve executable path\n");
    return 1;
  }
  if (snprintf(hash_path, sizeof(hash_path), "%s.sha256", exe_path) <= 0) {
    printf("[FAIL] cannot compose hash path\n");
    return 1;
  }

  FILE *fp = fopen(hash_path, "r");
  if (!fp) {
    printf("[FAIL] cannot read hash sidecar: %s\n", hash_path);
    return 1;
  }
  if (!fgets(original, sizeof(original), fp)) {
    fclose(fp);
    printf("[FAIL] cannot read original hash content\n");
    return 1;
  }
  fclose(fp);

  if (tamper_hash_file(hash_path, original) != 0) {
    printf("[FAIL] tamper hash file failed\n");
    return 1;
  }

  st = cm_run_integrity_check();
  printf("\nIntegrity Check B (tamper)\nInput: sidecar hash dimodifikasi 1 karakter\nExpected Output: CM_ERR_INTEGRITY\nResult Output: %s\n", cm_status_str(st));
  if (st != CM_ERR_INTEGRITY) {
    restore_hash_file(hash_path, original);
    printf("[FAIL] expected CM_ERR_INTEGRITY after tamper, got %s\n", cm_status_str(st));
    return 1;
  }

  if (restore_hash_file(hash_path, original) != 0) {
    printf("[FAIL] restore hash file failed\n");
    return 1;
  }

  st = cm_run_integrity_check();
  printf("\nIntegrity Check C (restore)\nInput: sidecar hash dipulihkan\nExpected Output: CM_OK\nResult Output: %s\n", cm_status_str(st));
  if (st != CM_OK) {
    printf("[FAIL] integrity check failed after restore: %s\n", cm_status_str(st));
    return 1;
  }

  printf("[PASS] integrity runtime hash compare + tamper/restore\n");
  return 0;
}
