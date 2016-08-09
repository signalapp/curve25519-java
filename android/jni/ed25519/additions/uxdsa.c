#include <string.h>
#include <stdio.h>
#include "ge.h"
#include "crypto_additions.h"

int uxdsa_sign(unsigned char* signature_out,
               const unsigned char* curve25519_privkey,
               const unsigned char* msg, const unsigned long msg_len,
               const unsigned char* random)
{
  unsigned char a[32];
  unsigned char A[32];
  ge_p3 Bu, ed_pubkey_point;
  unsigned char sigbuf[MAX_MSG_LEN + 160]; /* working buffer */
  unsigned char sign_bit = 0;

  if (msg_len > MAX_MSG_LEN) {
    memset(signature_out, 0, 96);
    return -1;
  }
  /* Convert the Curve25519 privkey to an Ed25519 public key */
  ge_scalarmult_base(&ed_pubkey_point, curve25519_privkey);
  ge_p3_tobytes(A, &ed_pubkey_point);

  /* Force Edwards sign bit to zero */
  sign_bit = A[31] & 0x80;
  if (sign_bit) {
    sc_neg(a, curve25519_privkey);
    A[31] &= 0x7F;
  }
  else
    memcpy(a, curve25519_privkey, 32);
  
  calculate_Bu_and_U(&Bu, signature_out, sigbuf, a, msg, msg_len);

  /* Perform an Ed25519 signature with explicit private key */
  crypto_usign_modified(sigbuf, msg, msg_len, a, A, random, &Bu, signature_out /*U*/);
  memmove(signature_out+32, sigbuf, 64);
  return 0;
}

int uxdsa_verify(const unsigned char* signature,
                 const unsigned char* curve25519_pubkey,
                 const unsigned char* msg, const unsigned long msg_len)
{
  fe mont_x; 
  fe ed_y;
  unsigned char ed_pubkey[32];
  unsigned long long some_retval;
  unsigned char verifybuf[MAX_MSG_LEN + 160]; /* working buffer */
  unsigned char verifybuf2[MAX_MSG_LEN + 160]; /* working buffer #2 ?? !!! */
  ge_p3 Bu;

  if (msg_len > MAX_MSG_LEN) {
    return -1;
  }

  calculate_Bu(&Bu, verifybuf, msg, msg_len);

  /* Convert the Curve25519 public key into an Ed25519 public key.  

     ed_y = (mont_x - 1) / (mont_x + 1)

     NOTE: mont_x=-1 is converted to ed_y=0 since fe_invert is mod-exp
  */
  fe_frombytes(mont_x, curve25519_pubkey);
  fe_montx_to_edy(ed_y, mont_x);
  fe_tobytes(ed_pubkey, ed_y);

  memmove(verifybuf, signature, 96);
  memmove(verifybuf+96, msg, msg_len);

  /* Then perform a signature verification, return 0 on success */
  /* The below call has a strange API: */
  /* verifybuf = U || h || s || message */
  /* verifybuf2 = internal to next call gets a copy of verifybuf, S gets 
     replaced with pubkey for hashing, then the whole thing gets zeroized
     (if bad sig), or contains a copy of msg (good sig) */
  return crypto_usign_open_modified(verifybuf2, &some_retval, verifybuf, 96 + msg_len, ed_pubkey, &Bu);
}
