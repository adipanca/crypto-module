#ifndef CM_ERROR_H
#define CM_ERROR_H

typedef enum {
  CM_OK = 0,
  CM_ERR_STATE = 1,
  CM_ERR_SELFTEST = 2,
  CM_ERR_INTEGRITY = 3,
  CM_ERR_ENTROPY = 4,
  CM_ERR_PARAM = 5,
  CM_ERR_CRYPTO = 6
} cm_status_t;

const char *cm_status_str(cm_status_t status);

#endif
