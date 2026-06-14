#include "cm_error.h"

const char *cm_status_str(cm_status_t status) {
  switch (status) {
    case CM_OK: return "CM_OK";
    case CM_ERR_STATE: return "CM_ERR_STATE";
    case CM_ERR_SELFTEST: return "CM_ERR_SELFTEST";
    case CM_ERR_INTEGRITY: return "CM_ERR_INTEGRITY";
    case CM_ERR_ENTROPY: return "CM_ERR_ENTROPY";
    case CM_ERR_PARAM: return "CM_ERR_PARAM";
    case CM_ERR_CRYPTO: return "CM_ERR_CRYPTO";
    default: return "CM_ERR_UNKNOWN";
  }
}
