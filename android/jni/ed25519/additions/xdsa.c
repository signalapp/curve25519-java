#include <string.h>
#include "ge.h"
#include "curve_sigs.h"
#include "crypto_sign.h"
#include "crypto_additions.h"


int xdsa_sign(unsigned char* signature_out,
              const unsigned char* curve25519_privkey,
              const unsigned char* msg, const unsigned long msg_len,
              const unsigned char* random)
{
  unsigned char a[32];
  unsigned char A[32];
  ge_p3 ed_pubkey_point;
  unsigned char sigbuf[MAX_MSG_LEN + 128]; /* working buffer */
  unsigned char sign_bit = 0;

  if (msg_len > MAX_MSG_LEN) {
    memset(signature_out, 0, 64);
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

  /* Perform an Ed25519 signature with explicit private key */
  crypto_sign_modified(sigbuf, msg, msg_len, a, A, random);
  memmove(signature_out, sigbuf, 64);
  return 0;
}

int xdsa_verify(const unsigned char* signature,
                const unsigned char* curve25519_pubkey,
                const unsigned char* msg, const unsigned long msg_len)
{
  fe mont_x;
  fe ed_y;
  unsigned char ed_pubkey[32];
  unsigned long long some_retval;
  unsigned char verifybuf[MAX_MSG_LEN + 64]; /* working buffer */
  unsigned char verifybuf2[MAX_MSG_LEN + 64]; /* working buffer #2 */

  if (msg_len > MAX_MSG_LEN) {
    return -1;
  }

  /* Convert the Curve25519 public key into an Ed25519 public key.

     ed_y = (mont_x - 1) / (mont_x + 1)

     NOTE: mont_x=-1 is converted to ed_y=0 since fe_invert is mod-exp
  */
  fe_frombytes(mont_x, curve25519_pubkey);
  fe_montx_to_edy(ed_y, mont_x);
  fe_tobytes(ed_pubkey, ed_y);

  memmove(verifybuf, signature, 64);
  memmove(verifybuf+64, msg, msg_len);

  /* Then perform a normal Ed25519 verification, return 0 on success */
  /* The below call has a strange API: */
  /* verifybuf = R || S || message */
  /* verifybuf2 = internal to next call gets a copy of verifybuf, S gets 
     replaced with pubkey for hashing, then the whole thing gets zeroized
     (if bad sig), or contains a copy of msg (good sig) */
  return crypto_sign_open_modified(verifybuf2, &some_retval, verifybuf, 64 + msg_len, ed_pubkey);
}
