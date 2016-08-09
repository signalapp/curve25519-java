
#ifndef __CRYPTO_ADDITIONS__
#define __CRYPTO_ADDITIONS__

#include "crypto_uint32.h"
#include "fe.h"
#include "ge.h"

#define MAX_MSG_LEN 256

/* aneg = -a */
void sc_neg(unsigned char *aneg, const unsigned char *a);

void fe_montx_to_edy(fe edy, const fe montx);
void ge_p3_to_montx(fe montx, const ge_p3 *ed);

void ge_scalarmult(ge_p3 *h, const unsigned char *a, const ge_p3 *A);

void elligator(fe out, const fe in);
void hash_to_point(ge_p3* out, const unsigned char* in, const unsigned long in_len);
void calculate_Bu(ge_p3* Bu, 
                  unsigned char* buf,
                  const unsigned char* msg, const unsigned long msg_len);
void calculate_Bu_and_U(ge_p3* Bu, 
                        unsigned char* U, 
                        unsigned char* buf,
                        const unsigned char* a,
                        const unsigned char* msg, const unsigned long msg_len);

int crypto_sign_modified(
  unsigned char *sm,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *sk, /* Curve/Ed25519 private key */
  const unsigned char *pk, /* Ed25519 public key */
  const unsigned char *random /* 64 bytes random to hash into nonce */
  );

int crypto_sign_open_modified(
  unsigned char *m,unsigned long long *mlen,
  const unsigned char *sm,unsigned long long smlen,
  const unsigned char *pk
  );

int crypto_usign_modified(
  unsigned char *sm,
  const unsigned char *M,unsigned long Mlen,
  const unsigned char *a, 
  const unsigned char *A,
  const unsigned char *random,
  const ge_p3 *Bu,
  const unsigned char *U);

int crypto_usign_open_modified(
  unsigned char *m,unsigned long long *mlen,
  const unsigned char *sm,unsigned long long smlen,
  const unsigned char *pk, ge_p3* Bu);


#endif
