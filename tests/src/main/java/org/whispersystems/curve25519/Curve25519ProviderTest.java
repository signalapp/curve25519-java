package org.whispersystems.curve25519;

import junit.framework.TestCase;

import static org.fest.assertions.Assertions.assertThat;

public abstract class Curve25519ProviderTest extends TestCase {

  protected abstract Curve25519Provider createProvider() throws NoSuchProviderException;

  public void testKeyGen() throws NoSuchProviderException {
    Curve25519Provider provider = createProvider();

    byte[] in  = new byte[32];
    byte[] out = null;

    in[0] = 123;

    for (int count=0; count < 1000; count++) {
      out = provider.generatePublicKey(in);
      System.arraycopy(out, 0, in, 0, 32);
    }

    byte[] result2 = new byte[]{(byte)0xa2, (byte)0x3c, (byte)0x84, (byte)0x09, (byte)0xf2,
                                (byte)0x93, (byte)0xb4, (byte)0x42, (byte)0x6a, (byte)0xf5,
                                (byte)0xe5, (byte)0xe7, (byte)0xca, (byte)0xee, (byte)0x22,
                                (byte)0xa0, (byte)0x01, (byte)0xc7, (byte)0x9a, (byte)0xca,
                                (byte)0x1a, (byte)0xf2, (byte)0xea, (byte)0xcb, (byte)0x4d,
                                (byte)0xdd, (byte)0xfa, (byte)0x05, (byte)0xf8, (byte)0xbc,
                                (byte)0x7f, (byte)0x37};

    assertThat(out).isEqualTo(result2);
  }

  public void testEcDh() throws NoSuchProviderException {
    Curve25519Provider provider = createProvider();

    byte[] p = new byte[32];
    byte[] q = null;
    byte[] n = new byte[32];

    p[0] = 100;
    n[0] = 100;

    n = provider.generatePrivateKey(n);

    for (int count=0; count < 1000; count++) {
      q = provider.calculateAgreement(n, p);
      System.arraycopy(q, 0, p, 0, 32);
      q = provider.calculateAgreement(n, p);
      System.arraycopy(q, 0, n, 0, 32);
      n = provider.generatePrivateKey(n);
    }

    byte[] result = new byte[]{(byte)0xce, (byte)0xb4, (byte)0x4e, (byte)0xd6, (byte)0x4a,
                               (byte)0xd4, (byte)0xc2, (byte)0xb5, (byte)0x43, (byte)0x9d,
                               (byte)0x25, (byte)0xde, (byte)0xb1, (byte)0x10, (byte)0xa8,
                               (byte)0xd7, (byte)0x2e, (byte)0xb3, (byte)0xe3, (byte)0x8e,
                               (byte)0xf4, (byte)0x8a, (byte)0x42, (byte)0x73, (byte)0xb1,
                               (byte)0x1b, (byte)0x4b, (byte)0x13, (byte)0x8d, (byte)0x17,
                               (byte)0xf9, (byte)0x34};

    assertThat(q).isEqualTo(result);
  }

  // FIXME: There's no actual vector here.  If verifySignature is broken and always returns true,
  // this test will pass.
  public void testSignVerify() throws NoSuchProviderException {
    Curve25519Provider provider = createProvider();

    byte[] msg     = new byte[100];
    byte[] sig_out = new byte[64];
    byte[] privkey = new byte[32];
    byte[] pubkey  = new byte[32];
    byte[] random  = new byte[64];

    privkey[0] = 123;

    for (int count=0; count < 1000; count++) {
      privkey = provider.generatePrivateKey(privkey);
      pubkey  = provider.generatePublicKey (privkey);
      sig_out = provider.calculateSignature(random, privkey, msg);

      assertTrue(provider.verifySignature(pubkey, msg, sig_out));

      System.arraycopy(sig_out, 0, privkey, 0, 32);
    }
  }
}
