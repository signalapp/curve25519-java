package org.whispersystems.curve25519;

import org.whispersystems.curve25519.java.Sha512;

public class J2meCurve25519Provider extends BaseJavaCurve25519Provider {

  private final BouncyCastleSha512Provider sha512Provider = new BouncyCastleSha512Provider();

  // @Override
  protected Sha512 getSha512() {
    return sha512Provider;
  }

  // @Override
  public byte[] getRandom(int length) {
    byte[] random = new byte[length];
    SecureRandom.getInstance().nextBytes(random);

    return random;
  }
}
