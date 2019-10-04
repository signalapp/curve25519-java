package org.whispersystems.curve25519;

import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;
import junit.framework.TestCase;

import java.util.Arrays;
import java.util.Random;

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

  public void testVRFSign() throws NoSuchProviderException, VrfSignatureVerificationFailedException {
    Curve25519Provider provider = createProvider();

    byte[] msg     = HexBin.decode("5468697320697320756E697175652E");
    byte[] privkey = HexBin.decode("38611D253BEA85A203805343B74A936D3B13B9E3121453E9740B6B827E337E5D");
    byte[] signature  = HexBin.decode("5D501685D744424DE3EF5CA49ECDDD880FA7421C975CDF94BAE48CA16EC0899737721200EED1A8B0D2D6852826A1EAB78B0DF27F35B3F3E89C96E7AE3DAAA30F037297547886E554AFFC81DE54B575768FB30493C537ECDD5A87577DEB7D8E03");

    byte[] sig_out = provider.calculateVrfSignature(new byte[32], privkey, msg);
    assertTrue(Arrays.equals(signature, sig_out));
  }

  public void testVRFVerify() throws NoSuchProviderException, VrfSignatureVerificationFailedException {
    Curve25519Provider provider = createProvider();

    byte[] msg     = HexBin.decode("5468697320697320756E697175652E");
    byte[] pubkey  = HexBin.decode("21F7345F56D9602F1523298F4F6FCECB14DDE2D5B9A9B48BCA8242681492B920");
    byte[] vrf  = HexBin.decode("45DC7B816B01B36CFA1645DCAE8AC9BC8E523CD86D007D19953F03E7D54554A0");
    byte[] signature  = HexBin.decode("5D501685D744424DE3EF5CA49ECDDD880FA7421C975CDF94BAE48CA16EC0899737721200EED1A8B0D2D6852826A1EAB78B0DF27F35B3F3E89C96E7AE3DAAA30F037297547886E554AFFC81DE54B575768FB30493C537ECDD5A87577DEB7D8E03");

    byte[] calc_vrf = provider.verifyVrfSignature(pubkey, msg, signature );
    assertTrue(Arrays.equals(vrf, calc_vrf));
  }

  public void testVRFSignVerify() throws NoSuchProviderException, VrfSignatureVerificationFailedException {
    Curve25519Provider provider = createProvider();

    byte[] msg     = HexBin.decode("CE0827E6381654D3FFBE22F546E00199B5761C1E541108E56D5A66213A1569E969A02B1D27D91553B69984010F25331A13EA62BA53B6F5B86DA11F8C22ABBF11D6839E11626D0FEF191BD2D5251D371F57C53240F7CD2B435BE6213C7C8F36D47F3DE23A");
    byte[] privkey = HexBin.decode("C80827E6381654D3FFBE22F546E00199B5761C1E541108E56D5A66213A156969");
    byte[] publickey = provider.generatePublicKey(privkey);
    byte[] random = HexBin.decode("B33734A591BAB70644D731530B67E8734C157DD72B796B7FA3D7FF6885D4C122");
    byte[] vrf = HexBin.decode("5669EC30C0F39E2696BB048B574236DEFA325D307116D6A89612958793192FF5");

    byte[] sig_out = provider.calculateVrfSignature(random, privkey, msg);
    byte[] calc_vrf = provider.verifyVrfSignature(publickey, msg, sig_out);
    assertTrue(Arrays.equals(calc_vrf, vrf));
  }

  public void testVRFFailedVerifyByMessage() throws NoSuchProviderException, VrfSignatureVerificationFailedException {
    Curve25519Provider provider = createProvider();

    byte[] msg     = HexBin.decode("5468697320697320756E697175652E");
    byte[] pubkey  = HexBin.decode("21F7345F56D9602F1523298F4F6FCECB14DDE2D5B9A9B48BCA8242681492B920");
    byte[] signature  = HexBin.decode("5D501685D744424DE3EF5CA49ECDDD880FA7421C975CDF94BAE48CA16EC0899737721200EED1A8B0D2D6852826A1EAB78B0DF27F35B3F3E89C96E7AE3DAAA30F037297547886E554AFFC81DE54B575768FB30493C537ECDD5A87577DEB7D8E03");

    msg[4] ^= 0xff;

    try {
      provider.verifyVrfSignature(pubkey, msg, signature);
      fail();
    } catch(VrfSignatureVerificationFailedException ignored) {}
  }

  public void testVRFFailedVerifyByPublicKey() throws NoSuchProviderException, VrfSignatureVerificationFailedException {
    Curve25519Provider provider = createProvider();

    byte[] msg     = HexBin.decode("5468697320697320756E697175652E");
    byte[] pubkey  = HexBin.decode("21F7345F56D9602F1523298F4F6FCECB14DDE2D5B9A9B48BCA8242681492B920");
    byte[] signature  = HexBin.decode("5D501685D744424DE3EF5CA49ECDDD880FA7421C975CDF94BAE48CA16EC0899737721200EED1A8B0D2D6852826A1EAB78B0DF27F35B3F3E89C96E7AE3DAAA30F037297547886E554AFFC81DE54B575768FB30493C537ECDD5A87577DEB7D8E03");

    pubkey[4] ^= 0xff;

    try {
      provider.verifyVrfSignature(pubkey, msg, signature);
      fail();
    } catch(VrfSignatureVerificationFailedException ignored) {}
  }

  public void testVRFFailedVerifyBySignature() throws NoSuchProviderException, VrfSignatureVerificationFailedException {
    Curve25519Provider provider = createProvider();

    byte[] msg     = HexBin.decode("5468697320697320756E697175652E");
    byte[] pubkey  = HexBin.decode("21F7345F56D9602F1523298F4F6FCECB14DDE2D5B9A9B48BCA8242681492B920");
    byte[] signature  = HexBin.decode("5D501685D744424DE3EF5CA49ECDDD880FA7421C975CDF94BAE48CA16EC0899737721200EED1A8B0D2D6852826A1EAB78B0DF27F35B3F3E89C96E7AE3DAAA30F037297547886E554AFFC81DE54B575768FB30493C537ECDD5A87577DEB7D8E03");

    signature[4] ^= 0xff;

    try {
      provider.verifyVrfSignature(pubkey, msg, signature);
      fail();
    } catch(VrfSignatureVerificationFailedException ignored) {}
  }

  public void testVRFIntegrationTest() throws NoSuchProviderException, VrfSignatureVerificationFailedException {
    Curve25519Provider provider = createProvider();
    Random r = new Random(1244);

    byte[] msg     = new byte[100];
    byte[] privkey;
    byte[] pubkey;
    byte[] random = new byte[64];

    for (int count=0; count < 1000; count++) {
      r.nextBytes(random);
      r.nextBytes(msg);

      privkey = provider.generatePrivateKey(msg);
      pubkey = provider.generatePublicKey(privkey);

      byte[] sig_out = provider.calculateVrfSignature(random, privkey, msg);
      byte[] sig_out2 = provider.calculateVrfSignature(random, privkey, msg);
      r.nextBytes(random);
      byte[] sig_out3 = provider.calculateVrfSignature(random, privkey, msg);

      assertTrue(Arrays.equals(sig_out, sig_out2));
      assertFalse(Arrays.equals(sig_out, sig_out3));

      byte[] vrf1 = provider.verifyVrfSignature(pubkey, msg, sig_out);
      byte[] vrf2 = provider.verifyVrfSignature(pubkey, msg, sig_out);

      assertTrue(Arrays.equals(vrf1, vrf2));
      assertFalse(provider.verifySignature(pubkey, msg, sig_out));

      try {
        byte[] wrongPubkey = pubkey.clone();
        wrongPubkey[3] ^= 0xff;
        provider.verifyVrfSignature(wrongPubkey, msg, sig_out);
        fail();
      } catch (VrfSignatureVerificationFailedException ignored) {}

      try {
        byte[] wrongMsg = msg.clone();
        wrongMsg[3] ^= 0xff;
        provider.verifyVrfSignature(pubkey, wrongMsg, sig_out);
        fail();
      } catch (VrfSignatureVerificationFailedException ignored) {}

      try {
        byte[] wrongSignature = sig_out.clone();
        wrongSignature[3] ^= 0xff;
        provider.verifyVrfSignature(pubkey, msg, wrongSignature);
        fail();
      } catch (VrfSignatureVerificationFailedException ignored) {}
    }
  }
}
