#include "ecdh_p256.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

int ecdh_p256_keygen(uint8_t priv[32], uint8_t pub[65]) {
  BN_CTX *bn_ctx = NULL;
  EC_GROUP *group = NULL;
  EC_POINT *pub_point = NULL;
  BIGNUM *order = NULL;
  BIGNUM *priv_bn = NULL;

  if (!priv || !pub) return -1;

  bn_ctx = BN_CTX_new();
  group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  if (!bn_ctx || !group) goto fail;

  pub_point = EC_POINT_new(group);
  order = BN_new();
  priv_bn = BN_new();
  if (!pub_point || !order || !priv_bn) goto fail;

  if (EC_GROUP_get_order(group, order, bn_ctx) != 1) goto fail;
  if (BN_rand_range(priv_bn, order) != 1) goto fail;
  if (BN_is_zero(priv_bn)) goto fail;

  if (EC_POINT_mul(group, pub_point, priv_bn, NULL, NULL, bn_ctx) != 1) goto fail;

  if (BN_bn2binpad(priv_bn, priv, 32) != 32) goto fail;
  if (EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED, pub, 65, bn_ctx) != 65) goto fail;

  BN_free(priv_bn);
  BN_free(order);
  EC_POINT_free(pub_point);
  EC_GROUP_free(group);
  BN_CTX_free(bn_ctx);
  return 0;

fail:
  if (priv_bn) BN_free(priv_bn);
  if (order) BN_free(order);
  if (pub_point) EC_POINT_free(pub_point);
  if (group) EC_GROUP_free(group);
  if (bn_ctx) BN_CTX_free(bn_ctx);
  return -1;
}

int ecdh_p256_shared(const uint8_t priv[32], const uint8_t peer_pub[65], uint8_t shared[32]) {
  BN_CTX *bn_ctx = NULL;
  EC_GROUP *group = NULL;
  EC_POINT *peer_point = NULL;
  EC_POINT *secret_point = NULL;
  BIGNUM *priv_bn = NULL;
  BIGNUM *x_bn = NULL;

  if (!priv || !peer_pub || !shared) return -1;

  bn_ctx = BN_CTX_new();
  group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  if (!bn_ctx || !group) goto fail;

  peer_point = EC_POINT_new(group);
  secret_point = EC_POINT_new(group);
  priv_bn = BN_bin2bn(priv, 32, NULL);
  x_bn = BN_new();
  if (!peer_point || !secret_point || !priv_bn || !x_bn) goto fail;

  if (EC_POINT_oct2point(group, peer_point, peer_pub, 65, bn_ctx) != 1) goto fail;
  if (EC_POINT_is_on_curve(group, peer_point, bn_ctx) != 1) goto fail;
  if (EC_POINT_mul(group, secret_point, NULL, peer_point, priv_bn, bn_ctx) != 1) goto fail;
  if (EC_POINT_get_affine_coordinates(group, secret_point, x_bn, NULL, bn_ctx) != 1) goto fail;
  if (BN_bn2binpad(x_bn, shared, 32) != 32) goto fail;

  BN_free(x_bn);
  BN_free(priv_bn);
  EC_POINT_free(secret_point);
  EC_POINT_free(peer_point);
  EC_GROUP_free(group);
  BN_CTX_free(bn_ctx);
  return 0;

fail:
  if (x_bn) BN_free(x_bn);
  if (priv_bn) BN_free(priv_bn);
  if (secret_point) EC_POINT_free(secret_point);
  if (peer_point) EC_POINT_free(peer_point);
  if (group) EC_GROUP_free(group);
  if (bn_ctx) BN_CTX_free(bn_ctx);
  return -1;
}
