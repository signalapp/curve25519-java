package org.whispersystems.curve25519;

import java.util.Arrays;
import java.util.Random;

public class NativeCurve25519Test extends Curve25519Test {

  private final byte[] PUBLIC_KEY  = new byte[]{(byte) 0x21, (byte) 0xf7, (byte) 0x34, (byte) 0x5f, (byte) 0x56, (byte) 0xd9, (byte) 0x60, (byte) 0x2f, (byte) 0x15, (byte) 0x23, (byte) 0x29, (byte) 0x8f, (byte) 0x4f, (byte) 0x6f, (byte) 0xce, (byte) 0xcb, (byte) 0x14, (byte) 0xdd, (byte) 0xe2, (byte) 0xd5, (byte) 0xb9, (byte) 0xa9, (byte) 0xb4, (byte) 0x8b, (byte) 0xca, (byte) 0x82, (byte) 0x42, (byte) 0x68, (byte) 0x14, (byte) 0x92, (byte) 0xb9, (byte) 0x20};
  private final byte[] PRIVATE_KEY = new byte[]{(byte) 0x38, (byte) 0x61, (byte) 0x1d, (byte) 0x25, (byte) 0x3b, (byte) 0xea, (byte) 0x85, (byte) 0xa2, (byte) 0x03, (byte) 0x80, (byte) 0x53, (byte) 0x43, (byte) 0xb7, (byte) 0x4a, (byte) 0x93, (byte) 0x6d, (byte) 0x3b, (byte) 0x13, (byte) 0xb9, (byte) 0xe3, (byte) 0x12, (byte) 0x14, (byte) 0x53, (byte) 0xe9, (byte) 0x74, (byte) 0x0b, (byte) 0x6b, (byte) 0x82, (byte) 0x7e, (byte) 0x33, (byte) 0x7e, (byte) 0x5d};

  private final byte[] MESSAGE     = new byte[]{(byte) 0x54, (byte) 0x68, (byte) 0x69, (byte) 0x73, (byte) 0x20, (byte) 0x69, (byte) 0x73, (byte) 0x20, (byte) 0x75, (byte) 0x6e, (byte) 0x69, (byte) 0x71, (byte) 0x75, (byte) 0x65, (byte) 0x2e};
  private final byte[] VRF         = new byte[]{(byte) 0x75, (byte) 0xad, (byte) 0x49, (byte) 0xbc, (byte) 0x95, (byte) 0x5f, (byte) 0x38, (byte) 0xdc, (byte) 0xf6, (byte) 0x5f, (byte) 0xb6, (byte) 0x72, (byte) 0x08, (byte) 0x6b, (byte) 0xd5, (byte) 0x09, (byte) 0xcb, (byte) 0x4b, (byte) 0x4c, (byte) 0x41, (byte) 0x04, (byte) 0x7d, (byte) 0xb1, (byte) 0x7e, (byte) 0xfd, (byte) 0xaf, (byte) 0xee, (byte) 0xbc, (byte) 0x33, (byte) 0x03, (byte) 0x71, (byte) 0xe6};

  @Override
  public void testCheckProvider() throws NoSuchProviderException {
    assertTrue(Curve25519.getInstance(getProviderName()).isNative());
  }

  @Override
  public String getProviderName() {
    return "native";
  }

  public void testUniqueSignatures() throws Exception {
    Curve25519KeyPair keys   = getInstance().generateKeyPair();
    Random            random = new Random(System.currentTimeMillis());

    for (int i=1;i<=256;i++) {
      byte[] message = new byte[i];
      random.nextBytes(message);

      byte[] signature = getInstance().calculateVrfSignature(keys.getPrivateKey(), message);
      byte[] vrf       = getInstance().verifyVrfSignature(keys.getPublicKey(), message, signature);

      assertFalse(getInstance().verifySignature(keys.getPublicKey(), message, signature));

      message[Math.abs(random.nextInt()) % message.length] ^= 0x01;

      try {
        getInstance().verifyVrfSignature(keys.getPublicKey(), message, signature);
        throw new AssertionError("Should have failed");
      } catch (VrfSignatureVerificationFailedException e) {
        // good
      }
    }
  }

  public void testUniqueSignatureVector() throws Exception {
    Curve25519KeyPair keys      = new Curve25519KeyPair(PUBLIC_KEY, PRIVATE_KEY);
    byte[]            signature = getInstance().calculateVrfSignature(keys.getPrivateKey(), MESSAGE);
    byte[]            vrf       = getInstance().verifyVrfSignature(keys.getPublicKey(), MESSAGE, signature);

    assertTrue(Arrays.equals(vrf, VRF));
  }


}
