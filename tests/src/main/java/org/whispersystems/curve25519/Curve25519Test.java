package org.whispersystems.curve25519;

import junit.framework.TestCase;
import org.whispersystems.curve25519.java.ed25519.ge_p3_tobytes;
import org.whispersystems.curve25519.java.ed25519.ge_scalarmult;
import org.whispersystems.curve25519.java.ge_frombytes;
import org.whispersystems.curve25519.java.ge_p3;
import org.whispersystems.curve25519.java.ed25519.ge_neg;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.fest.assertions.Assertions.assertThat;
import static org.whispersystems.curve25519.java.ed25519.ge_isneutral.ge_isneutral;
import static org.whispersystems.curve25519.java.ge_scalarmult_base.ge_scalarmult_base;


public abstract class Curve25519Test extends TestCase {

  public abstract void testCheckProvider() throws NoSuchProviderException;
  public abstract String getProviderName();

  public void testAgreement() throws NoSuchProviderException {

    byte[] alicePublic  = {(byte) 0x1b, (byte) 0xb7, (byte) 0x59, (byte) 0x66,
                           (byte) 0xf2, (byte) 0xe9, (byte) 0x3a, (byte) 0x36, (byte) 0x91,
                           (byte) 0xdf, (byte) 0xff, (byte) 0x94, (byte) 0x2b, (byte) 0xb2,
                           (byte) 0xa4, (byte) 0x66, (byte) 0xa1, (byte) 0xc0, (byte) 0x8b,
                           (byte) 0x8d, (byte) 0x78, (byte) 0xca, (byte) 0x3f, (byte) 0x4d,
                           (byte) 0x6d, (byte) 0xf8, (byte) 0xb8, (byte) 0xbf, (byte) 0xa2,
                           (byte) 0xe4, (byte) 0xee, (byte) 0x28};

    byte[] alicePrivate = {(byte) 0xc8, (byte) 0x06, (byte) 0x43, (byte) 0x9d, (byte) 0xc9,
                           (byte) 0xd2, (byte) 0xc4, (byte) 0x76, (byte) 0xff, (byte) 0xed,
                           (byte) 0x8f, (byte) 0x25, (byte) 0x80, (byte) 0xc0, (byte) 0x88,
                           (byte) 0x8d, (byte) 0x58, (byte) 0xab, (byte) 0x40, (byte) 0x6b,
                           (byte) 0xf7, (byte) 0xae, (byte) 0x36, (byte) 0x98, (byte) 0x87,
                           (byte) 0x90, (byte) 0x21, (byte) 0xb9, (byte) 0x6b, (byte) 0xb4,
                           (byte) 0xbf, (byte) 0x59};

    byte[] bobPublic    = {(byte) 0x65, (byte) 0x36, (byte) 0x14, (byte) 0x99,
                           (byte) 0x3d, (byte) 0x2b, (byte) 0x15, (byte) 0xee, (byte) 0x9e,
                           (byte) 0x5f, (byte) 0xd3, (byte) 0xd8, (byte) 0x6c, (byte) 0xe7,
                           (byte) 0x19, (byte) 0xef, (byte) 0x4e, (byte) 0xc1, (byte) 0xda,
                           (byte) 0xae, (byte) 0x18, (byte) 0x86, (byte) 0xa8, (byte) 0x7b,
                           (byte) 0x3f, (byte) 0x5f, (byte) 0xa9, (byte) 0x56, (byte) 0x5a,
                           (byte) 0x27, (byte) 0xa2, (byte) 0x2f};

    byte[] bobPrivate   = {(byte) 0xb0, (byte) 0x3b, (byte) 0x34, (byte) 0xc3, (byte) 0x3a,
                           (byte) 0x1c, (byte) 0x44, (byte) 0xf2, (byte) 0x25, (byte) 0xb6,
                           (byte) 0x62, (byte) 0xd2, (byte) 0xbf, (byte) 0x48, (byte) 0x59,
                           (byte) 0xb8, (byte) 0x13, (byte) 0x54, (byte) 0x11, (byte) 0xfa,
                           (byte) 0x7b, (byte) 0x03, (byte) 0x86, (byte) 0xd4, (byte) 0x5f,
                           (byte) 0xb7, (byte) 0x5d, (byte) 0xc5, (byte) 0xb9, (byte) 0x1b,
                           (byte) 0x44, (byte) 0x66};

    byte[] shared       = {(byte) 0x32, (byte) 0x5f, (byte) 0x23, (byte) 0x93, (byte) 0x28,
                           (byte) 0x94, (byte) 0x1c, (byte) 0xed, (byte) 0x6e, (byte) 0x67,
                           (byte) 0x3b, (byte) 0x86, (byte) 0xba, (byte) 0x41, (byte) 0x01,
                           (byte) 0x74, (byte) 0x48, (byte) 0xe9, (byte) 0x9b, (byte) 0x64,
                           (byte) 0x9a, (byte) 0x9c, (byte) 0x38, (byte) 0x06, (byte) 0xc1,
                           (byte) 0xdd, (byte) 0x7c, (byte) 0xa4, (byte) 0xc4, (byte) 0x77,
                           (byte) 0xe6, (byte) 0x29};

    byte[] sharedOne = getInstance().calculateAgreement(bobPublic, alicePrivate);
    byte[] sharedTwo = getInstance().calculateAgreement(alicePublic, bobPrivate);

    assertThat(sharedOne).isEqualTo(shared);
    assertThat(sharedTwo).isEqualTo(shared);
  }

  public void testRandomAgreements() throws NoSuchAlgorithmException, NoSuchProviderException {
    for (int i=0;i<50;i++) {
      Curve25519KeyPair alice = getInstance().generateKeyPair();
      Curve25519KeyPair bob   = getInstance().generateKeyPair();

      byte[] sharedAlice = getInstance().calculateAgreement(bob.getPublicKey(), alice.getPrivateKey());
      byte[] sharedBob   = getInstance().calculateAgreement(alice.getPublicKey(), bob.getPrivateKey());

      assertThat(sharedAlice).isEqualTo(sharedBob);
    }
  }

  public void testSignature() throws NoSuchProviderException {
    byte[] aliceIdentityPrivate = {(byte)0xc0, (byte)0x97, (byte)0x24, (byte)0x84, (byte)0x12,
                                   (byte)0xe5, (byte)0x8b, (byte)0xf0, (byte)0x5d, (byte)0xf4,
                                   (byte)0x87, (byte)0x96, (byte)0x82, (byte)0x05, (byte)0x13,
                                   (byte)0x27, (byte)0x94, (byte)0x17, (byte)0x8e, (byte)0x36,
                                   (byte)0x76, (byte)0x37, (byte)0xf5, (byte)0x81, (byte)0x8f,
                                   (byte)0x81, (byte)0xe0, (byte)0xe6, (byte)0xce, (byte)0x73,
                                   (byte)0xe8, (byte)0x65};

    byte[] aliceIdentityPublic  = {(byte)0xab, (byte)0x7e, (byte)0x71, (byte)0x7d,
                                   (byte)0x4a, (byte)0x16, (byte)0x3b, (byte)0x7d, (byte)0x9a,
                                   (byte)0x1d, (byte)0x80, (byte)0x71, (byte)0xdf, (byte)0xe9,
                                   (byte)0xdc, (byte)0xf8, (byte)0xcd, (byte)0xcd, (byte)0x1c,
                                   (byte)0xea, (byte)0x33, (byte)0x39, (byte)0xb6, (byte)0x35,
                                   (byte)0x6b, (byte)0xe8, (byte)0x4d, (byte)0x88, (byte)0x7e,
                                   (byte)0x32, (byte)0x2c, (byte)0x64};

    byte[] aliceEphemeralPublic = {(byte)0x05, (byte)0xed, (byte)0xce, (byte)0x9d, (byte)0x9c,
                                   (byte)0x41, (byte)0x5c, (byte)0xa7, (byte)0x8c, (byte)0xb7,
                                   (byte)0x25, (byte)0x2e, (byte)0x72, (byte)0xc2, (byte)0xc4,
                                   (byte)0xa5, (byte)0x54, (byte)0xd3, (byte)0xeb, (byte)0x29,
                                   (byte)0x48, (byte)0x5a, (byte)0x0e, (byte)0x1d, (byte)0x50,
                                   (byte)0x31, (byte)0x18, (byte)0xd1, (byte)0xa8, (byte)0x2d,
                                   (byte)0x99, (byte)0xfb, (byte)0x4a};

    byte[] aliceSignature       = {(byte)0x5d, (byte)0xe8, (byte)0x8c, (byte)0xa9, (byte)0xa8,
                                   (byte)0x9b, (byte)0x4a, (byte)0x11, (byte)0x5d, (byte)0xa7,
                                   (byte)0x91, (byte)0x09, (byte)0xc6, (byte)0x7c, (byte)0x9c,
                                   (byte)0x74, (byte)0x64, (byte)0xa3, (byte)0xe4, (byte)0x18,
                                   (byte)0x02, (byte)0x74, (byte)0xf1, (byte)0xcb, (byte)0x8c,
                                   (byte)0x63, (byte)0xc2, (byte)0x98, (byte)0x4e, (byte)0x28,
                                   (byte)0x6d, (byte)0xfb, (byte)0xed, (byte)0xe8, (byte)0x2d,
                                   (byte)0xeb, (byte)0x9d, (byte)0xcd, (byte)0x9f, (byte)0xae,
                                   (byte)0x0b, (byte)0xfb, (byte)0xb8, (byte)0x21, (byte)0x56,
                                   (byte)0x9b, (byte)0x3d, (byte)0x90, (byte)0x01, (byte)0xbd,
                                   (byte)0x81, (byte)0x30, (byte)0xcd, (byte)0x11, (byte)0xd4,
                                   (byte)0x86, (byte)0xce, (byte)0xf0, (byte)0x47, (byte)0xbd,
                                   (byte)0x60, (byte)0xb8, (byte)0x6e, (byte)0x88};

    if (!getInstance().verifySignature(aliceIdentityPublic, aliceEphemeralPublic, aliceSignature)) {
      throw new AssertionError("Sig verification failed!");
    }

    for (int i=0;i<aliceSignature.length;i++) {
      byte[] modifiedSignature = new byte[aliceSignature.length];
      System.arraycopy(aliceSignature, 0, modifiedSignature, 0, modifiedSignature.length);

      modifiedSignature[i] ^= 0x01;

      if (getInstance().verifySignature(aliceIdentityPublic, aliceEphemeralPublic, modifiedSignature)) {
        throw new AssertionError("Sig verification succeeded!");
      }
    }
  }

  public void testLargeSignatures() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {
    Curve25519KeyPair keys      = getInstance().generateKeyPair();
    byte[]            message   = new byte[1024 * 1024];
    byte[]            signature = getInstance().calculateSignature(keys.getPrivateKey(), message);

    assertTrue(getInstance().verifySignature(keys.getPublicKey(), message, signature));

    signature[0] ^= 0x01;

    assertFalse(getInstance().verifySignature(keys.getPublicKey(), message, signature));
  }

  public void testVRFSignatures() throws NoSuchProviderException, IllegalArgumentException{
    Curve25519KeyPair keys      = getInstance().generateKeyPair();
    byte[]            message1   = new byte[1024];
    byte[]            message2   = new byte[ 512];
    byte[]            signature1 = getInstance().calculateVrfSignature(keys.getPrivateKey(), message1);
    byte[]            signature2 = getInstance().calculateVrfSignature(keys.getPrivateKey(), message2);

    try {
      byte[]            vrf_out   = getInstance().verifyVrfSignature(keys.getPublicKey(), message1, signature1);
    } catch (VrfSignatureVerificationFailedException e) {
      throw new AssertionError("Sig verification failed!");
    }

    try {
      byte[]            vrf_out   = getInstance().verifyVrfSignature(keys.getPublicKey(), message1, signature2);
      throw new AssertionError("Sig verification succeeded!");
    } catch (VrfSignatureVerificationFailedException e) {
    }
  }
  
  public void testGeScalarMult() {
    byte[] B_bytes = {
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    };

  byte[] misc_bytes = {
          (byte) 0x57, (byte) 0x17, (byte) 0xfa, (byte) 0xce, (byte) 0xca, (byte) 0xb9, (byte) 0xdf, (byte) 0x0e,
          (byte) 0x90, (byte) 0x67, (byte) 0xaa, (byte) 0x46, (byte) 0xba, (byte) 0x83, (byte) 0x2f, (byte) 0xeb,
          (byte) 0x1c, (byte) 0x49, (byte) 0xd0, (byte) 0x21, (byte) 0xb1, (byte) 0x33, (byte) 0xff, (byte) 0x11,
          (byte) 0xc9, (byte) 0x7a, (byte) 0xb8, (byte) 0xcf, (byte) 0xe3, (byte) 0x29, (byte) 0x46, (byte) 0x17,
    };

    byte[] q_scalar = {
            (byte) 0xed, (byte) 0xd3, (byte) 0xf5, (byte) 0x5c, (byte) 0x1a, (byte) 0x63, (byte) 0x12, (byte) 0x58,
            (byte) 0xd6, (byte) 0x9c, (byte) 0xf7, (byte) 0xa2, (byte) 0xde, (byte) 0xf9, (byte) 0xde, (byte) 0x14,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x10,
    };

    byte[] c_scalar = {
              0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    byte[] neutral_bytes = {
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };


    ge_p3 point1 = new ge_p3(), point2 = new ge_p3(), B_point = new ge_p3(), misc_point = new ge_p3(), miscneg_point = new ge_p3();


    byte[] output1 = new byte[32], output2 = new byte[32];
    if (ge_frombytes.ge_frombytes_negate_vartime(B_point, B_bytes) != 0)
      throw new AssertionError("Ge From Bytes Negate Var Time Failed!");
    if (ge_frombytes.ge_frombytes_negate_vartime(miscneg_point, misc_bytes) != 0)
      throw new AssertionError("Ge From Bytes Negate Var Time Failed!");
    ge_neg.ge_neg(B_point, B_point);
    ge_neg.ge_neg(misc_point, miscneg_point);


    ge_scalarmult_base(point1,  q_scalar);
    ge_scalarmult.ge_scalarmult(point2, q_scalar, B_point);
    ge_p3_tobytes.ge_p3_tobytes(output1, point1);
    ge_p3_tobytes.ge_p3_tobytes(output2, point2);
    if (!java.util.Arrays.equals(output1, neutral_bytes))
      throw new AssertionError("Ge Scalar Multiplaction Failed!");
    if (!java.util.Arrays.equals(output1, output2))
      throw new AssertionError("Ge Scalar Multiplaction Failed!");
    if (ge_isneutral(point1 ) != 1 && ge_isneutral(point2)==1 && ge_isneutral(B_point) != 0)
      throw new AssertionError("Ge Scalar Multiplaction Failed!");

  }

  protected Curve25519 getInstance() throws NoSuchProviderException {
    return Curve25519.getInstance(getProviderName());
  }


}
