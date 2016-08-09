#include <string.h>
#include "fe.h"
#include "ge.h"
#include "crypto_uint32.h"
#include "crypto_hash_sha512.h"
#include "crypto_additions.h"

unsigned int legendre_is_nonsquare(fe in)
{
  fe temp;
  fe_pow22523(temp, in);  /* temp = in^((q-5)/8) */
  fe_sq(temp, temp);      /*        in^((q-5)/4) */ 
  fe_sq(temp, temp);      /*        in^((q-5)/2) */
  fe_mul(temp, temp, in); /*        in^((q-3)/2) */
  fe_mul(temp, temp, in); /*        in^((q-1)/2) */

  /* temp is now the Legendre symbol:
   * 1  = square
   * 0  = input is zero
   * -1 = nonsquare
   */
  unsigned char bytes[32];
  fe_tobytes(bytes, temp);
  return 1 & bytes[31];
}

void elligator(fe mont_x, const fe in)
{
  /* r = in
   * v = -A/(1+2r^2)
   * e = (v^3 + Av^2 + v)^((q-1)/2) # legendre symbol
   * if e == 1 (square) or e == 0 (because v == 0 and 2r^2 + 1 == 0)
   *   out = v
   * if e == -1 (nonsquare)
   *   out = -v - A
   */
  fe A, one, twor2, twor2plus1, twor2plus1inv;
  fe v, v2, v3, Av2, e, u, Atemp, uneg;
  unsigned int nonsquare;

  fe_0(one);
  one[0] = 1;                            /* 1 */
  fe_0(A);
  A[0] = 486662;                         /* A = 486662 */

  fe_sq2(twor2, in);                     /* 2r^2 */
  fe_add(twor2plus1, twor2, one);        /* 1+2r^2 */
  fe_invert(twor2plus1inv, twor2plus1);  /* 1/(1+2r^2) */
  fe_mul(v, twor2plus1inv, A);           /* A/(1+2r^2) */
  fe_neg(v, v);                          /* v = -A/(1+2r^2) */

  fe_sq(v2, v);                          /* v^2 */
  fe_mul(v3, v2, v);                     /* v^3 */
  fe_mul(Av2, v2, A);                    /* Av^2 */
  fe_add(e, v3, Av2);                    /* v^3 + Av^2 */
  fe_add(e, e, v);                       /* v^3 + Av^2 + v */
  nonsquare = legendre_is_nonsquare(e); 

  fe_0(Atemp);
  fe_cmov(Atemp, A, nonsquare);          /* 0, or A if nonsquare */
  fe_add(u, v, Atemp);                   /* v, or v+A if nonsquare */ 
  fe_neg(uneg, u);                       /* -v, or -v-A if nonsquare */
  fe_cmov(u, uneg, nonsquare);           /* v, or -v-A if nonsquare */
  fe_copy(mont_x, u);
}

void hash_to_point(ge_p3* out, const unsigned char* in, const unsigned long in_len)
{
  unsigned char hash[64];
  fe h, mont_x;
  unsigned char sign_bit;

  /* hash and elligator */
  crypto_hash_sha512(hash, in, in_len);

  sign_bit = hash[31] & 0x80; /* take the high bit as Edwards sign bit */
  hash[31] &= 0x7F;
  fe_frombytes(h, hash); 

  elligator(mont_x, h);
  
  fe ed_y;
  unsigned char ed_pubkey[32];

  fe_montx_to_edy(ed_y, mont_x);
  fe_tobytes(ed_pubkey, ed_y);
  ed_pubkey[31] &= 0x7F;  /* bit should be zero already, but just in case */
  ed_pubkey[31] |= sign_bit;

  /* decompress full point */
  /* WARNING - due to timing-variance, don't use with secret inputs! */
  ge_frombytes_negate_vartime(out, ed_pubkey);

  /* undo the negation */
  fe_neg(out->X, out->X);
  fe_neg(out->T, out->T);

  /* multiply by 8 (cofactor) to map onto the main subgroup,
   * or map small-order points to the neutral element
   * (the latter prevents leaking r mod (2, 4, 8) via U) */
  ge_p1p1 dbl_result;

  ge_p3_dbl(&dbl_result, out);
  ge_p1p1_to_p3(out, &dbl_result);

  ge_p3_dbl(&dbl_result, out);
  ge_p1p1_to_p3(out, &dbl_result);

  ge_p3_dbl(&dbl_result, out);
  ge_p1p1_to_p3(out, &dbl_result);
}


void calculate_Bu(ge_p3* Bu, 
                 unsigned char* buf,
                 const unsigned char* msg, const unsigned long msg_len)
{
  int count;

  /* Calculate SHA512(label(2) || msg) */
  buf[0] = 0xFD;
  for (count = 1; count < 32; count++)
    buf[count] = 0xFF;
  memmove(buf+32, msg, msg_len); 

  hash_to_point(Bu, buf, 32 + msg_len);
}


void calculate_Bu_and_U(ge_p3* Bu, 
                       unsigned char* U, 
                       unsigned char* buf,
                       const unsigned char* a,
                       const unsigned char* msg, const unsigned long msg_len)
{
  ge_p3 p3;

  calculate_Bu(Bu, buf, msg, msg_len);
  ge_scalarmult(&p3, a, Bu);
  ge_p3_tobytes(U, &p3);
}
