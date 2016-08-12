package org.whispersystems.curve25519;

import java.util.Random;

public class NativeCurve25519Test extends Curve25519Test {

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

      byte[] signature = getInstance().calculateUniqueSignature(keys.getPrivateKey(), message);

      assertTrue(getInstance().verifyUniqueSignature(keys.getPublicKey(), message, signature));
      assertFalse(getInstance().verifySignature(keys.getPublicKey(), message, signature));

      message[Math.abs(random.nextInt()) % message.length] ^= 0x01;

      assertFalse(getInstance().verifyUniqueSignature(keys.getPublicKey(), message, signature));
    }

  }


}
