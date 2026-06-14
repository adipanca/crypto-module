#ifndef CM_FSM_H
#define CM_FSM_H

#include "cm_error.h"
#include "cm_types.h"

cm_status_t cm_set_state(cm_module_ctx_t *ctx, cm_state_t next_state);
int cm_is_operational(const cm_module_ctx_t *ctx);

#endif
