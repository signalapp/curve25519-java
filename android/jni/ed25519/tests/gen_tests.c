#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "crypto_hash_sha512.h"
#include "keygen.h"
#include "crypto_additions.h"
#include "ge.h"
#include "utility.h"
#include "tests.h"
#include "xeddsa.h"
#include "gen_x.h"
#include "gen_eddsa.h"
#include "gen_veddsa.h"
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


int generalized_xeddsa_fast_test(int silent)
{
  unsigned char signature1[64];
  unsigned char signature2[64];
  unsigned char privkey[32];
  unsigned char pubkey[32];
  unsigned char msg1[1000];
  unsigned char msg2[1000];
  unsigned char random[64];

  memset(signature1, 0, 64);
  memset(signature2, 0, 64);
  memset(privkey, 0xF0, 32);
  memset(pubkey, 2, 32);
  memset(msg1, 0x10, 1000);
  memset(msg2, 0x20, 1000);
  memset(random, 0xBC, 64);

  sc_clamp(privkey);
  curve25519_keygen(pubkey, privkey);

  msg2[0] = 1;
  TEST("generalized xeddsa sign #1", generalized_xeddsa_25519_sign(signature1, privkey, msg1, 100, random, NULL, 0) == 0);
  TEST("generalized xeddsa sign #2", generalized_xeddsa_25519_sign(signature2, privkey, msg2, 100, random, NULL, 0) == 0);

  TEST("generalized (old) xeddsa verify #1", xed25519_verify(signature1, pubkey, msg1, 100) == 0);
  TEST("generalized (old) xeddsa verify #2", xed25519_verify(signature2, pubkey, msg2, 100) == 0);
  TEST("generalized (old) xeddsa verify #3", xed25519_verify(signature1, pubkey, msg2, 100) != 0);
  TEST("generalized (old) xeddsa verify #4", xed25519_verify(signature2, pubkey, msg1, 100) != 0);

  TEST("generalized xeddsa verify #1", generalized_xeddsa_25519_verify(signature1, pubkey, msg1, 100, NULL, 0) == 0);
  TEST("generalized xeddsa verify #2", generalized_xeddsa_25519_verify(signature2, pubkey, msg2, 100, NULL, 0) == 0);
  TEST("generalized xeddsa verify #3", generalized_xeddsa_25519_verify(signature1, pubkey, msg2, 100, NULL, 0) != 0);
  TEST("generalized xeddsa verify #4", generalized_xeddsa_25519_verify(signature2, pubkey, msg1, 100, NULL, 0) != 0);
  return 0;
}

int generalized_xveddsa_fast_test(int silent)
{
  unsigned char signature1[96];
  unsigned char signature2[96];
  unsigned char privkey[32];
  unsigned char pubkey[32];
  unsigned char msg1[1000];
  unsigned char msg2[1000];
  unsigned char random[64];
  unsigned char vrf[32];

  memset(signature1, 0, 64);
  memset(signature2, 0, 64);
  memset(privkey, 1, 32);
  memset(pubkey, 2, 32);
  memset(msg1, 0x11, 1000);
  memset(msg2, 0x22, 1000);
  memset(random, 0xAB, 64);

  sc_clamp(privkey);
  curve25519_keygen(pubkey, privkey);

  msg2[0] ^= 1;
  TEST("generalized xveddsa sign #1", generalized_xveddsa_25519_sign(signature1, privkey, msg1, 100, random, NULL, 0) == 0);
  TEST("generalized xveddsa sign #2", generalized_xveddsa_25519_sign(signature2, privkey, msg2, 100, random, (unsigned char*)"abc", 3) == 0);

  TEST("generalized xveddsa verify #1", generalized_xveddsa_25519_verify(vrf, signature1, pubkey, msg1, 100, NULL, 0) == 0);
  TEST("generalized xveddsa verify #2", generalized_xveddsa_25519_verify(vrf, signature2, pubkey, msg2, 100, (unsigned char*)"abc", 3) == 0);
  TEST("generalized xveddsa verify #3", generalized_xveddsa_25519_verify(vrf, signature1, pubkey, msg2, 100, NULL, 0) != 0);
  TEST("generalized xveddsa verify #4", generalized_xveddsa_25519_verify(vrf, signature2, pubkey, msg1, 100, (unsigned char*)"abc", 3) != 0);


  unsigned char signature3[96];
  unsigned char vrf3[96];
  random[0] ^= 1;
  TEST("generalized xveddsa sign #3", generalized_xveddsa_25519_sign(signature3, privkey, msg1, 100, random, NULL, 0) == 0);
  TEST("generalized xveddsa verify #5", generalized_xveddsa_25519_verify(vrf, signature1, pubkey, msg1, 100, NULL, 0) == 0);
  TEST("generalized xveddsa verify #6", generalized_xveddsa_25519_verify(vrf3, signature3, pubkey, msg1, 100, NULL, 0) == 0);
  TEST("generalized xveddsa VRFs equal", memcmp(vrf, vrf3, 32) == 0);
  TEST("generalized xveddsa Kv equal", memcmp(signature1+0, signature3+0, 32) == 0);
  TEST("generalized xveddsa h not equal", memcmp(signature1+32, signature3+32, 32) != 0);
  TEST("generalized xveddsa s not equal", memcmp(signature1+64, signature3+64, 32) != 0);
  return 0;
}


int generalized_xveddsa_slow_test(int silent, int iterations)
{
  unsigned char signature_10k_correct[96] = {
    0x1e, 0x83, 0x2a, 0xc7, 0x6c, 0xba, 0x00, 0x69, 
    0x45, 0x87, 0x32, 0x17, 0xa8, 0xf2, 0x45, 0xf6, 
    0x93, 0x40, 0x8c, 0x0b, 0x15, 0x5a, 0xf2, 0x9b, 
    0xf6, 0x6c, 0x9f, 0x8f, 0xa9, 0x23, 0x12, 0x69, 
    0x4c, 0x94, 0x37, 0xb6, 0xde, 0x19, 0x5d, 0x21, 
    0x90, 0x9e, 0x08, 0xd9, 0xfd, 0xc2, 0x9e, 0x81, 
    0x13, 0x5c, 0x6b, 0xcf, 0xdf, 0x5d, 0x1c, 0x15, 
    0xf3, 0xea, 0x36, 0x5c, 0x45, 0x73, 0xfd, 0x0b, 
    0x62, 0x75, 0x37, 0xe1, 0x4c, 0x69, 0xd4, 0x71, 
    0x58, 0xeb, 0x7d, 0x76, 0xbe, 0xb7, 0x51, 0xd0, 
    0x6b, 0x3d, 0xb2, 0xc2, 0xeb, 0x15, 0x95, 0xa5, 
    0xfa, 0xf8, 0x96, 0xb3, 0xda, 0xb4, 0x86, 0x05, 
  };
  unsigned char signature_100k_correct[96] = {
    0xd8, 0xf0, 0x19, 0xea, 0x3f, 0x3a, 0x14, 0xfe, 
    0xf2, 0x86, 0x4a, 0xf8, 0xdb, 0x98, 0xd3, 0x87, 
    0x81, 0x47, 0x44, 0xeb, 0xce, 0xdf, 0x80, 0x95, 
    0x0b, 0x4c, 0x5b, 0x26, 0x51, 0x4c, 0x29, 0x91, 
    0x1f, 0x05, 0xbf, 0xfd, 0x4e, 0xba, 0x2d, 0x9b, 
    0x4f, 0xc4, 0xe4, 0x9d, 0xc3, 0xeb, 0xcf, 0xf5, 
    0x19, 0xe2, 0x77, 0xb0, 0x20, 0x1d, 0x45, 0xf9, 
    0xbb, 0x8e, 0xe7, 0xaf, 0xa3, 0x51, 0xd8, 0x07, 
    0x27, 0x20, 0x5b, 0x50, 0xdd, 0x5a, 0x7a, 0x1a, 
    0x3c, 0x36, 0x61, 0x26, 0x3b, 0xc7, 0x90, 0x21, 
    0xe8, 0xbc, 0x27, 0x10, 0xe7, 0x80, 0x60, 0x12, 
    0x45, 0x0b, 0x63, 0x10, 0xeb, 0xbb, 0x2b, 0x06, 
  };


/*
  unsigned char signature_1m_correct[96] = {
  0xf8, 0xb1, 0x20, 0xf2, 0x1e, 0x5c, 0xbf, 0x5f, 
  0xea, 0x07, 0xcb, 0xb5, 0x77, 0xb8, 0x03, 0xbc, 
  0xcb, 0x6d, 0xf1, 0xc1, 0xa5, 0x03, 0x05, 0x7b, 
  0x01, 0x63, 0x9b, 0xf9, 0xed, 0x3e, 0x57, 0x47, 
  0xd2, 0x5b, 0xf4, 0x7e, 0x7c, 0x45, 0xce, 0xfc, 
  0x06, 0xb3, 0xf4, 0x05, 0x81, 0x9f, 0x53, 0xb0, 
  0x18, 0xe3, 0xfa, 0xcb, 0xb2, 0x52, 0x3e, 0x57, 
  0xcb, 0x34, 0xcc, 0x81, 0x60, 0xb9, 0x0b, 0x04, 
  0x07, 0x79, 0xc0, 0x53, 0xad, 0xc4, 0x4b, 0xd0, 
  0xb5, 0x7d, 0x95, 0x4e, 0xbe, 0xa5, 0x75, 0x0c, 
  0xd4, 0xbf, 0xa7, 0xc0, 0xcf, 0xba, 0xe7, 0x7c, 
  0xe2, 0x90, 0xef, 0x61, 0xa9, 0x29, 0x66, 0x0d,
  };

  unsigned char signature_10m_correct[96] = {
  0xf5, 0xa4, 0xbc, 0xec, 0xc3, 0x3d, 0xd0, 0x43, 
  0xd2, 0x81, 0x27, 0x9e, 0xf0, 0x4c, 0xbe, 0xf3, 
  0x77, 0x01, 0x56, 0x41, 0x0e, 0xff, 0x0c, 0xb9, 
  0x66, 0xec, 0x4d, 0xe0, 0xb7, 0x25, 0x63, 0x6b, 
  0x5c, 0x08, 0x39, 0x80, 0x4e, 0x37, 0x1b, 0x2c, 
  0x46, 0x6f, 0x86, 0x99, 0x1c, 0x4e, 0x31, 0x60, 
  0xdb, 0x4c, 0xfe, 0xc5, 0xa2, 0x4d, 0x71, 0x2b, 
  0xd6, 0xd0, 0xc3, 0x98, 0x88, 0xdb, 0x0e, 0x0c, 
  0x68, 0x4a, 0xd3, 0xc7, 0x56, 0xac, 0x8d, 0x95, 
  0x7b, 0xbd, 0x99, 0x50, 0xe8, 0xd3, 0xea, 0xf3, 
  0x7b, 0x26, 0xf2, 0xa2, 0x2b, 0x02, 0x58, 0xca, 
  0xbd, 0x2c, 0x2b, 0xf7, 0x77, 0x58, 0xfe, 0x09,
  };
  */

  int count;  
  const int MSG_LEN  = 200;
  unsigned char privkey[32];
  unsigned char pubkey[32];
  unsigned char signature[96];
  unsigned char msg[MSG_LEN];
  unsigned char random[64];
  unsigned char vrf_out[32];

  memset(privkey, 0, 32);
  memset(pubkey, 0, 32);
  memset(signature, 3, 96);
  memset(msg, 0, MSG_LEN);
  memset(random, 0, 64);

  INFO("Pseudorandom XVEdDSA...\n");
  for (count = 1; count <= iterations; count++) {
    unsigned char b[64];
    crypto_hash_sha512(b, signature, 96);
    memmove(privkey, b, 32);
    crypto_hash_sha512(b, privkey, 32);
    memmove(random, b, 64);

    sc_clamp(privkey);
    curve25519_keygen(pubkey, privkey);

    generalized_xveddsa_25519_sign(signature, privkey, msg, MSG_LEN, random, NULL, 0);

    if (generalized_xveddsa_25519_verify(vrf_out, signature, pubkey, msg, MSG_LEN, NULL, 0) != 0)
      ERROR("XVEdDSA verify failure #1 %d\n", count);

    if (b[63] & 1)
      signature[count % 96] ^= 1;
    else
      msg[count % MSG_LEN] ^= 1;

    if (generalized_xveddsa_25519_verify(vrf_out, signature, pubkey, msg, MSG_LEN, NULL, 0) == 0)
      ERROR("XVEdDSA verify failure #2 %d\n", count);

    if (count == 10000)
      print_bytes("10K XVEdDSA", signature, 96);
    if (count == 100000)
      print_bytes("100K XVEdDSA", signature, 96);
    if (count == 1000000)
      print_bytes("1M XVEdDSA", signature, 96);
    if (count == 10000000)
      print_bytes("10M XVEdDSA", signature, 96);
    if (count == 100000000)
      print_bytes("100M XVEdDSA", signature, 96);

    /*
    if (count == 10000) {
      if (memcmp(signature, signature_10k_correct, 96) != 0)
        ERROR("XVEDDSA 10K doesn't match %d\n", count);
    }
    if (count == 100000) {
      if (memcmp(signature, signature_100k_correct, 96) != 0)
        ERROR("VXEDDSA 100K doesn't match %d\n", count);
    }
    if (count == 1000000) {
      if (memcmp(signature, signature_1m_correct, 96) != 0)
        ERROR("VXEDDSA 1m doesn't match %d\n", count);
    }
    if (count == 10000000) {
      if (memcmp(signature, signature_10m_correct, 96) != 0)
        ERROR("VXEDDSA 10m doesn't match %d\n", count);
    }
    if (count == 100000000) {
      if (memcmp(signature, signature_100m_correct, 96) != 0)
        ERROR("VXEDDSA 100m doesn't match %d\n", count);
    }
    */
  }
  INFO("good\n");
  return 0;
}

int generalized_all_fast_tests(int silent)
{
  int result;
  if ((result = generalized_xeddsa_fast_test(silent)) != 0)
    return result;
  if ((result = generalized_xveddsa_fast_test(silent)) != 0)
    return result;

  return 0;
}

