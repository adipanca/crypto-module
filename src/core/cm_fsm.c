#include "cm_fsm.h"

cm_status_t cm_set_state(cm_module_ctx_t *ctx, cm_state_t next_state) {
  if (!ctx) return CM_ERR_PARAM;
  ctx->state = next_state;
  return CM_OK;
}

int cm_is_operational(const cm_module_ctx_t *ctx) {
  if (!ctx) return 0;
  return (ctx->state == INITIALIZED &&
          ctx->selftest_done &&
          ctx->integrity_ok &&
          ctx->entropy_ok);
}
