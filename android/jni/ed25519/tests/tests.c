#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "crypto_hash_sha512.h"
#include "keygen.h"
#include "curve_sigs.h"
#include "xeddsa.h"
#include "uxeddsa.h"
#include "crypto_additions.h"
#include "ge.h"
#include "utility.h"
#include "tests.h"
#include <assert.h>


#define ERROR(...) do {if (!silent) { printf(__VA_ARGS__); abort(); } else return -1; } while (0)
#define INFO(...) do {if (!silent) printf(__VA_ARGS__);} while (0)

#define TEST(msg, cond) \
  do {  \
    if ((cond)) { \
      INFO("%s good\n", msg); \
    } \
    else { \
      ERROR("%s BAD!!!\n", msg); \
    } \
  } while (0)


int sha512_fast_test(int silent)
{
  unsigned char sha512_input[112] =   
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
  unsigned char sha512_correct_output[64] =
    {
    0x8E, 0x95, 0x9B, 0x75, 0xDA, 0xE3, 0x13, 0xDA,
    0x8C, 0xF4, 0xF7, 0x28, 0x14, 0xFC, 0x14, 0x3F,
    0x8F, 0x77, 0x79, 0xC6, 0xEB, 0x9F, 0x7F, 0xA1,
    0x72, 0x99, 0xAE, 0xAD, 0xB6, 0x88, 0x90, 0x18,
    0x50, 0x1D, 0x28, 0x9E, 0x49, 0x00, 0xF7, 0xE4,
    0x33, 0x1B, 0x99, 0xDE, 0xC4, 0xB5, 0x43, 0x3A,
    0xC7, 0xD3, 0x29, 0xEE, 0xB6, 0xDD, 0x26, 0x54,
    0x5E, 0x96, 0xE5, 0x5B, 0x87, 0x4B, 0xE9, 0x09
    };
  unsigned char sha512_actual_output[64];

  crypto_hash_sha512(sha512_actual_output, sha512_input, sizeof(sha512_input));
  TEST("SHA512 #1", memcmp(sha512_actual_output, sha512_correct_output, 64) == 0);

  sha512_input[111] ^= 1;

  crypto_hash_sha512(sha512_actual_output, sha512_input, sizeof(sha512_input));
  TEST("SHA512 #2", memcmp(sha512_actual_output, sha512_correct_output, 64) != 0);

  return 0;
}

int ge_is_small_order_test(int silent)
{
  ge_p3 o1, o2, o4a, o4b; 

  fe zero, one, minusone;
  fe_0(zero);
  fe_1(one);
  fe_sub(minusone, zero, one);

  // o1 is the neutral point (order 1)
  fe_copy(o1.X, zero);
  fe_copy(o1.Y, one);
  fe_copy(o1.Z, one);
  fe_mul(o1.T, o1.X, o1.Y);
 
  // o2 is the order 2 point
  fe_copy(o2.X, zero);
  fe_copy(o2.Y, minusone);
  fe_copy(o2.Z, one);
  fe_mul(o2.T, o2.X, o2.Y);

  /* TODO check order 8 points */

  /* sqrt(-1) */
  static unsigned char i_bytes[32] = {
    0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4,
    0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
    0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b,
    0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b
  };
  fe i;
  fe_frombytes(i, i_bytes);

  fe_copy(o4a.X, i);
  fe_copy(o4a.Y, zero);
  fe_copy(o4a.Z, one);
  fe_mul(o4a.T, o4a.X, o4a.Y);

  fe_neg(o4b.X, o4a.X);
  fe_copy(o4b.Y, zero);
  fe_copy(o4b.Z, one);
  fe_mul(o4b.T, o4b.X, o4b.Y);


  TEST("ge_is_small_order #1", 
      ge_is_small_order(&o1) && ge_is_small_order(&o2) &&
      ge_is_small_order(&o4a) && ge_is_small_order(&o4b));

  ge_p3 B0, B1, B2, B100;
  unsigned char scalar[32];
  memset(scalar, 0, 32);

  ge_scalarmult_base(&B0, scalar);
  scalar[0] = 1;
  ge_scalarmult_base(&B1, scalar);
  scalar[0] = 2;
  ge_scalarmult_base(&B2, scalar);
  scalar[0] = 100;
  ge_scalarmult_base(&B100, scalar);

  TEST("ge_is_small_order #2", 
      ge_is_small_order(&B0) && 
      !ge_is_small_order(&B1) && 
      !ge_is_small_order(&B2) &&
      !ge_is_small_order(&B100));

  return 0;
}


int elligator_fast_test(int silent)
{
  unsigned char elligator_correct_output[32] = 
  {
  0x5f, 0x35, 0x20, 0x00, 0x1c, 0x6c, 0x99, 0x36, 
  0xa3, 0x12, 0x06, 0xaf, 0xe7, 0xc7, 0xac, 0x22, 
  0x4e, 0x88, 0x61, 0x61, 0x9b, 0xf9, 0x88, 0x72, 
  0x44, 0x49, 0x15, 0x89, 0x9d, 0x95, 0xf4, 0x6e
  };

  unsigned char hashtopoint_correct_output1[32] = 
  {
  0xce, 0x89, 0x9f, 0xb2, 0x8f, 0xf7, 0x20, 0x91,
  0x5e, 0x14, 0xf5, 0xb7, 0x99, 0x08, 0xab, 0x17,
  0xaa, 0x2e, 0xe2, 0x45, 0xb4, 0xfc, 0x2b, 0xf6,
  0x06, 0x36, 0x29, 0x40, 0xed, 0x7d, 0xe7, 0xed
  };

  unsigned char hashtopoint_correct_output2[32] = 
  {
  0xa0, 0x35, 0xbb, 0xa9, 0x4d, 0x30, 0x55, 0x33, 
  0x0d, 0xce, 0xc2, 0x7f, 0x83, 0xde, 0x79, 0xd0, 
  0x89, 0x67, 0x72, 0x4c, 0x07, 0x8d, 0x68, 0x9d, 
  0x61, 0x52, 0x1d, 0xf9, 0x2c, 0x5c, 0xba, 0x77
  };

  unsigned char calculateu_correct_output[32] = 
  {
  0xa8, 0x36, 0xb5, 0x30, 0xd3, 0xe7, 0x65, 0x54, 
  0x3e, 0x72, 0xc8, 0x87, 0x7d, 0xa4, 0x12, 0x6d, 
  0x77, 0xbf, 0x22, 0x0b, 0x72, 0xd5, 0xad, 0x6b, 
  0xb6, 0xc2, 0x16, 0xb2, 0x92, 0x5f, 0x0f, 0x2a
  };

  int count;
  fe in, out;
  unsigned char bytes[32];
  fe_0(in);
  fe_0(out);
  for (count = 0; count < 32; count++) {
    bytes[count] = count;
  }
  fe_frombytes(in, bytes);
  elligator(out, in);
  fe_tobytes(bytes, out);
  TEST("Elligator vector", memcmp(bytes, elligator_correct_output, 32) == 0);

  /* Elligator(0) == 0 test */
  fe_0(in);
  elligator(out, in);
  TEST("Elligator(0) == 0", memcmp(in, out, 32) == 0);

  /* ge_montx_to_p2(0) -> order2 point test */
  fe one, negone, zero;
  fe_1(one);
  fe_0(zero);
  fe_sub(negone, zero, one);
  ge_p2 p2;
  ge_montx_to_p2(&p2, zero, 0);
  TEST("ge_montx_to_p2(0) == order 2 point", 
      fe_isequal(p2.X, zero) &&
      fe_isequal(p2.Y, negone) &&
      fe_isequal(p2.Z, one));

  /* Hash to point vector test */
  ge_p3 p3;
  unsigned char htp[32];
  
  for (count=0; count < 32; count++) {
    htp[count] = count;
  }

  hash_to_point(&p3, htp, 32);
  ge_p3_tobytes(htp, &p3);
  TEST("hash_to_point #1", memcmp(htp, hashtopoint_correct_output1, 32) == 0);

  for (count=0; count < 32; count++) {
    htp[count] = count+1;
  }

  hash_to_point(&p3, htp, 32);
  ge_p3_tobytes(htp, &p3);
  TEST("hash_to_point #2", memcmp(htp, hashtopoint_correct_output2, 32) == 0);

  /* calculate_U vector test */
  ge_p3 Bu;
  unsigned char U[32];
  unsigned char Ubuf[200];
  unsigned char a[32];
  unsigned char Umsg[3];
  Umsg[0] = 0;
  Umsg[1] = 1;
  Umsg[2] = 2;
  for (count=0; count < 32; count++) {
    a[count] = 8 + count;
  }
  sc_clamp(a);
  calculate_Bu_and_U(&Bu, U, Ubuf, a, Umsg, 3);
  TEST("calculate_Bu_and_U vector", memcmp(U, calculateu_correct_output, 32) == 0);
  return 0;
}

int curvesigs_fast_test(int silent)
{
  unsigned char signature_correct[64] = {
    0xcf, 0x87, 0x3d, 0x03, 0x79, 0xac, 0x20, 0xe8, 
    0x89, 0x3e, 0x55, 0x67, 0xee, 0x0f, 0x89, 0x51, 
    0xf8, 0xdb, 0x84, 0x0d, 0x26, 0xb2, 0x43, 0xb4, 
    0x63, 0x52, 0x66, 0x89, 0xd0, 0x1c, 0xa7, 0x18, 
    0xac, 0x18, 0x9f, 0xb1, 0x67, 0x85, 0x74, 0xeb, 
    0xdd, 0xe5, 0x69, 0x33, 0x06, 0x59, 0x44, 0x8b, 
    0x0b, 0xd6, 0xc1, 0x97, 0x3f, 0x7d, 0x78, 0x0a, 
    0xb3, 0x95, 0x18, 0x62, 0x68, 0x03, 0xd7, 0x82,
  };
  const int MSG_LEN  = 200;
  unsigned char privkey[32];
  unsigned char pubkey[32];
  unsigned char signature[64];
  unsigned char msg[MSG_LEN];
  unsigned char random[64];

  memset(privkey, 0, 32);
  memset(pubkey, 0, 32);
  memset(signature, 0, 64);
  memset(msg, 0, MSG_LEN);
  memset(random, 0, 64);

  privkey[8] = 189; /* just so there's some bits set */
  sc_clamp(privkey);
  
  /* Signature vector test */
  curve25519_keygen(pubkey, privkey);

  curve25519_sign(signature, privkey, msg, MSG_LEN, random);

  TEST("Curvesig sign", memcmp(signature, signature_correct, 64) == 0);
  TEST("Curvesig verify #1", curve25519_verify(signature, pubkey, msg, MSG_LEN) == 0);
  signature[0] ^= 1;
  TEST("Curvesig verify #2", curve25519_verify(signature, pubkey, msg, MSG_LEN) != 0);
  return 0;
}

int xeddsa_fast_test(int silent)
{
  unsigned char signature_correct[64] = {
  0x11, 0xc7, 0xf3, 0xe6, 0xc4, 0xdf, 0x9e, 0x8a, 
  0x51, 0x50, 0xe1, 0xdb, 0x3b, 0x30, 0xf9, 0x2d, 
  0xe3, 0xa3, 0xb3, 0xaa, 0x43, 0x86, 0x56, 0x54, 
  0x5f, 0xa7, 0x39, 0x0f, 0x4b, 0xcc, 0x7b, 0xb2, 
  0x6c, 0x43, 0x1d, 0x9e, 0x90, 0x64, 0x3e, 0x4f, 
  0x0e, 0xaa, 0x0e, 0x9c, 0x55, 0x77, 0x66, 0xfa, 
  0x69, 0xad, 0xa5, 0x76, 0xd6, 0x3d, 0xca, 0xf2, 
  0xac, 0x32, 0x6c, 0x11, 0xd0, 0xb9, 0x77, 0x02,
  };
  const int MSG_LEN  = 200;
  unsigned char privkey[32];
  unsigned char pubkey[32];
  unsigned char signature[64];
  unsigned char msg[MSG_LEN];
  unsigned char random[64];

  memset(privkey, 0, 32);
  memset(pubkey, 0, 32);
  memset(signature, 0, 64);
  memset(msg, 0, MSG_LEN);
  memset(random, 0, 64);

  privkey[8] = 189; /* just so there's some bits set */
  sc_clamp(privkey);
  
  /* Signature vector test */
  curve25519_keygen(pubkey, privkey);

  xed25519_sign(signature, privkey, msg, MSG_LEN, random);
  TEST("XEdDSA sign", memcmp(signature, signature_correct, 64) == 0);
  TEST("XEdDSA verify #1", xed25519_verify(signature, pubkey, msg, MSG_LEN) == 0);
  signature[0] ^= 1;
  TEST("XEdDSA verify #2", xed25519_verify(signature, pubkey, msg, MSG_LEN) != 0);
  return 0;
}

int uxeddsa_fast_test(int silent)
{
  unsigned char signature_correct[96] = {
  0x66, 0x51, 0x0b, 0x68, 0x9e, 0xb7, 0xd8, 0x55, 
  0x04, 0x62, 0xaf, 0x52, 0x0c, 0x89, 0x69, 0xe8, 
  0xa9, 0xa5, 0x3d, 0xf3, 0x8e, 0xd6, 0xe6, 0x0f, 
  0xe8, 0xfe, 0xd6, 0xa8, 0x95, 0x66, 0x9c, 0x19, 
  0x66, 0x4a, 0x65, 0x25, 0xff, 0xb7, 0x47, 0x74, 
  0x8e, 0x86, 0x40, 0x55, 0x0f, 0xb1, 0x4a, 0xd1, 
  0x6d, 0xe0, 0x3d, 0x51, 0xa2, 0xd3, 0x4d, 0xee, 
  0x64, 0x7e, 0x35, 0x98, 0x42, 0x25, 0x5a, 0x02, 
  0xf8, 0x8c, 0x1e, 0x23, 0x5b, 0xd5, 0x7f, 0xb9, 
  0x98, 0x60, 0x55, 0x63, 0xd6, 0xe0, 0x6d, 0xa1, 
  0x29, 0xd9, 0xfc, 0xee, 0x1c, 0x08, 0x6d, 0x5a, 
  0x28, 0xa1, 0x27, 0xf0, 0x06, 0xb9, 0x79, 0x03
  };
  const int MSG_LEN  = 200;
  unsigned char privkey[32];
  unsigned char pubkey[32];
  unsigned char signature[96];
  unsigned char msg[MSG_LEN];
  unsigned char random[64];

  memset(privkey, 0, 32);
  memset(pubkey, 0, 32);
  memset(signature, 0, 96);
  memset(msg, 0, MSG_LEN);
  memset(random, 0, 64);

  privkey[8] = 189; /* just so there's some bits set */
  sc_clamp(privkey);
  
  /* Signature vector test */
  curve25519_keygen(pubkey, privkey);

  uxed25519_sign(signature, privkey, msg, MSG_LEN, random);

  TEST("UXEdDSA sign", memcmp(signature, signature_correct, 96) == 0);
  TEST("UXEdDSA verify #1", uxed25519_verify(signature, pubkey, msg, MSG_LEN) == 0);
  signature[0] ^= 1;
  TEST("UXEdDSA verify #2", uxed25519_verify(signature, pubkey, msg, MSG_LEN) != 0);

  /* Test U */
  unsigned char sigprev[96];
  memcpy(sigprev, signature, 96);
  sigprev[0] ^= 1; /* undo prev disturbance */

  random[0] ^= 1; 
  uxed25519_sign(signature, privkey, msg, MSG_LEN, random);
 
  TEST("UXEdDSA U value changed", memcmp(signature, sigprev, 32) == 0);
  TEST("UXEdDSA (h, s) changed", memcmp(signature+32, sigprev+32, 64) != 0);
  return 0;
}

int curvesigs_slow_test(int silent, int iterations)
{

  unsigned char signature_10k_correct[64] = {
  0xfc, 0xba, 0x55, 0xc4, 0x85, 0x4a, 0x42, 0x25, 
  0x19, 0xab, 0x08, 0x8d, 0xfe, 0xb5, 0x13, 0xb6, 
  0x0d, 0x24, 0xbb, 0x16, 0x27, 0x55, 0x71, 0x48, 
  0xdd, 0x20, 0xb1, 0xcd, 0x2a, 0xd6, 0x7e, 0x35, 
  0xef, 0x33, 0x4c, 0x7b, 0x6d, 0x94, 0x6f, 0x52, 
  0xec, 0x43, 0xd7, 0xe6, 0x35, 0x24, 0xcd, 0x5b, 
  0x5d, 0xdc, 0xb2, 0x32, 0xc6, 0x22, 0x53, 0xf3, 
  0x38, 0x02, 0xf8, 0x28, 0x28, 0xc5, 0x65, 0x05,
  };

  int count;  
  const int MSG_LEN  = 200;
  unsigned char privkey[32];
  unsigned char pubkey[32];
  unsigned char signature[64];
  unsigned char msg[MSG_LEN];
  unsigned char random[64];

  memset(privkey, 0, 32);
  memset(pubkey, 0, 32);
  memset(signature, 0, 64);
  memset(msg, 0, MSG_LEN);
  memset(random, 0, 64);

  /* Signature random test */
  INFO("Pseudorandom curvesigs...\n");
  for (count = 1; count <= iterations; count++) {
    unsigned char b[64];
    crypto_hash_sha512(b, signature, 64);
    memmove(privkey, b, 32);
    crypto_hash_sha512(b, privkey, 32);
    memmove(random, b, 64);

    sc_clamp(privkey);
    curve25519_keygen(pubkey, privkey);

    curve25519_sign(signature, privkey, msg, MSG_LEN, random);

    if (curve25519_verify(signature, pubkey, msg, MSG_LEN) != 0)
      ERROR("Curvesig verify failure #1 %d\n", count);

    if (b[63] & 1)
      signature[count % 64] ^= 1;
    else
      msg[count % MSG_LEN] ^= 1;
    if (curve25519_verify(signature, pubkey, msg, MSG_LEN) == 0)
      ERROR("Curvesig verify failure #2 %d\n", count);
      
    if (count == 10000) {
      if (memcmp(signature, signature_10k_correct, 64) != 0)
        ERROR("Curvesig signature 10K doesn't match %d\n", count);
    }
    if (count == 100000)
      print_bytes("100K curvesigs", signature, 64);
    if (count == 1000000)
      print_bytes("1M curvesigs", signature, 64);
    if (count == 10000000)
      print_bytes("10M curvesigs", signature, 64);
  }
  INFO("good\n");
  return 0;
}

int xeddsa_slow_test(int silent, int iterations)
{

  unsigned char signature_10k_correct[64] = {
  0x15, 0x29, 0x03, 0x38, 0x66, 0x16, 0xcd, 0x26, 
  0xbb, 0x3e, 0xec, 0xe2, 0x9f, 0x72, 0xa2, 0x5c, 
  0x7d, 0x05, 0xc9, 0xcb, 0x84, 0x3f, 0x92, 0x96, 
  0xb3, 0xfb, 0xb9, 0xdd, 0xd6, 0xed, 0x99, 0x04, 
  0xc1, 0xa8, 0x02, 0x16, 0xcf, 0x49, 0x3f, 0xf1, 
  0xbe, 0x69, 0xf9, 0xf1, 0xcc, 0x16, 0xd7, 0xdc, 
  0x6e, 0xd3, 0x78, 0xaa, 0x04, 0xeb, 0x71, 0x51, 
  0x9d, 0xe8, 0x7a, 0x5b, 0xd8, 0x49, 0x7b, 0x05, 
  };

  int count;  
  const int MSG_LEN  = 200;
  unsigned char privkey[32];
  unsigned char pubkey[32];
  unsigned char signature[96];
  unsigned char msg[MSG_LEN];
  unsigned char random[64];

  memset(privkey, 0, 32);
  memset(pubkey, 0, 32);
  memset(signature, 1, 64);
  memset(msg, 0, MSG_LEN);
  memset(random, 0, 64);

  /* Signature random test */
  INFO("Pseudorandom XEdDSA...\n");
  for (count = 1; count <= iterations; count++) {
    unsigned char b[64];
    crypto_hash_sha512(b, signature, 64);
    memmove(privkey, b, 32);
    crypto_hash_sha512(b, privkey, 32);
    memmove(random, b, 64);

    sc_clamp(privkey);
    curve25519_keygen(pubkey, privkey);

    xed25519_sign(signature, privkey, msg, MSG_LEN, random);

    if (xed25519_verify(signature, pubkey, msg, MSG_LEN) != 0)
      ERROR("XEdDSA verify failure #1 %d\n", count);

    if (b[63] & 1)
      signature[count % 64] ^= 1;
    else
      msg[count % MSG_LEN] ^= 1;
    if (xed25519_verify(signature, pubkey, msg, MSG_LEN) == 0)
      ERROR("XEdDSA verify failure #2 %d\n", count);

    if (count == 10000) {
      if (memcmp(signature, signature_10k_correct, 64) != 0)
        ERROR("XEDSA signature 10K doesn't match %d\n", count);
    }
    if (count == 100000)
      print_bytes("100K XEdDSA", signature, 64);
    if (count == 1000000)
      print_bytes("1M XEdDSA", signature, 64);
    if (count == 10000000)
      print_bytes("10M XEdDSA", signature, 64);
  }
  INFO("good\n");
  return 0;
}

int xeddsa_to_curvesigs_slow_test(int silent, int iterations)
{

  unsigned char signature_10k_correct[64] = {
  0x33, 0x50, 0xa8, 0x68, 0xcd, 0x9e, 0x74, 0x99, 
  0xa3, 0x5c, 0x33, 0x75, 0x2b, 0x22, 0x03, 0xf8, 
  0xb5, 0x0f, 0xea, 0x8c, 0x33, 0x1c, 0x68, 0x8b, 
  0xbb, 0xf3, 0x31, 0xcf, 0x7c, 0x42, 0x37, 0x35,  
  0xa0, 0x0e, 0x15, 0xb8, 0x5d, 0x2b, 0xe1, 0xa2, 
  0x03, 0x77, 0x94, 0x3d, 0x13, 0x5c, 0xd4, 0x9b, 
  0x6a, 0x31, 0xf4, 0xdc, 0xfe, 0x24, 0xad, 0x54, 
  0xeb, 0xd2, 0x98, 0x47, 0xf1, 0xcc, 0xbf, 0x0d
  
  };

  int count;  
  const int MSG_LEN  = 200;
  unsigned char privkey[32];
  unsigned char pubkey[32];
  unsigned char signature[96];
  unsigned char msg[MSG_LEN];
  unsigned char random[64];

  memset(privkey, 0, 32);
  memset(pubkey, 0, 32);
  memset(signature, 2, 64);
  memset(msg, 0, MSG_LEN);
  memset(random, 0, 64);

  /* Signature random test */
  INFO("Pseudorandom XEdDSA/Curvesigs...\n");
  for (count = 1; count <= iterations; count++) {
    unsigned char b[64];
    crypto_hash_sha512(b, signature, 64);
    memmove(privkey, b, 32);
    crypto_hash_sha512(b, privkey, 32);
    memmove(random, b, 64);

    sc_clamp(privkey);
    curve25519_keygen(pubkey, privkey);

    xed25519_sign(signature, privkey, msg, MSG_LEN, random);

    if (curve25519_verify(signature, pubkey, msg, MSG_LEN) != 0)
      ERROR("XEdDSA/Curvesigs verify failure #1 %d\n", count);

    if (b[63] & 1)
      signature[count % 64] ^= 1;
    else
      msg[count % MSG_LEN] ^= 1;
    if (curve25519_verify(signature, pubkey, msg, MSG_LEN) == 0)
      ERROR("XEdDSA/Curvesigs verify failure #2 %d\n", count);

    if (count == 10000) {
      if (memcmp(signature, signature_10k_correct, 64) != 0)
        ERROR("XEdDSA/Curvesigs signature 10K doesn't match %d\n", count);
    }
    if (count == 100000)
      print_bytes("100K XEdDSA/C", signature, 64);
    if (count == 1000000)
      print_bytes("1M XEdDSA/C", signature, 64);
    if (count == 10000000)
      print_bytes("10M XEdDSA/C", signature, 64);
  }
  INFO("good\n");
  return 0;
}

int uxeddsa_slow_test(int silent, int iterations)
{

  unsigned char signature_10k_correct[96] = {
  0x2d, 0x2a, 0x69, 0x20, 0x0a, 0xe7, 0x76, 0xeb, 
  0x08, 0xc0, 0x3b, 0x4f, 0x26, 0x82, 0xd5, 0x3c, 
  0x97, 0xc6, 0xb7, 0x9c, 0x6a, 0xf6, 0x24, 0x91, 
  0xe1, 0xf9, 0x8f, 0x4f, 0x23, 0xc4, 0xba, 0x28, 
  0x4b, 0x60, 0x87, 0x07, 0xe5, 0x94, 0xcb, 0xda, 
  0x1b, 0x03, 0x5a, 0xd4, 0xd0, 0x6d, 0xd9, 0xa0, 
  0x6a, 0x07, 0xee, 0x7b, 0x98, 0x7c, 0xe1, 0xc4, 
  0x91, 0x52, 0x0d, 0x08, 0x32, 0xd7, 0x10, 0x03, 
  0xbd, 0x96, 0x34, 0x11, 0x0c, 0x44, 0x56, 0x95, 
  0x8b, 0x87, 0xdb, 0x12, 0x97, 0xa9, 0x5a, 0x62, 
  0x2a, 0x34, 0xb1, 0xb1, 0xe2, 0xb4, 0xf5, 0x3c, 
  0x34, 0xb6, 0x69, 0x0b, 0x77, 0x0e, 0x49, 0x07,
  };

  int count;  
  const int MSG_LEN  = 200;
  unsigned char privkey[32];
  unsigned char pubkey[32];
  unsigned char signature[96];
  unsigned char msg[MSG_LEN];
  unsigned char random[64];

  memset(privkey, 0, 32);
  memset(pubkey, 0, 32);
  memset(signature, 3, 96);
  memset(msg, 0, MSG_LEN);
  memset(random, 0, 64);

  INFO("Pseudorandom UXEdDSA...\n");
  for (count = 1; count <= iterations; count++) {
    unsigned char b[64];
    crypto_hash_sha512(b, signature, 96);
    memmove(privkey, b, 32);
    crypto_hash_sha512(b, privkey, 32);
    memmove(random, b, 64);

    sc_clamp(privkey);
    curve25519_keygen(pubkey, privkey);

    uxed25519_sign(signature, privkey, msg, MSG_LEN, random);

    if (uxed25519_verify(signature, pubkey, msg, MSG_LEN) != 0)
      ERROR("UXEdDSA verify failure #1 %d\n", count);

    if (b[63] & 1)
      signature[count % 96] ^= 1;
    else
      msg[count % MSG_LEN] ^= 1;

    if (uxed25519_verify(signature, pubkey, msg, MSG_LEN) == 0)
      ERROR("UXEdDSA verify failure #2 %d\n", count);

    if (count == 10000) {
      if (memcmp(signature, signature_10k_correct, 96) != 0)
        ERROR("UXEDDSA 10K doesn't match %d\n", count);
    }

    if (count == 100000)
      print_bytes("100K UXEdDSA", signature, 96);
    if (count == 1000000)
      print_bytes("1M UXEdDSA", signature, 96);
    if (count == 10000000)
      print_bytes("10M UXEdDSA", signature, 96);
  }
  INFO("good\n");
  return 0;
}

int all_fast_tests(int silent)
{
  int result;
  if ((result = sha512_fast_test(silent)) != 0)
    return result;
  if ((result = ge_is_small_order_test(silent)) != 0)
    return result;
  if ((result = elligator_fast_test(silent)) != 0)
    return result;
  if ((result = curvesigs_fast_test(silent)) != 0)
    return result;
  if ((result = xeddsa_fast_test(silent)) != 0)
    return result;
  if ((result = uxeddsa_fast_test(silent)) != 0)
    return result;

  return 0;
}

