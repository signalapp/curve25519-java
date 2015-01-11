package org.whispersystems.curve25519;

import org.whispersystems.curve25519.java.Sha512;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class JavaCurve25519Provider extends BaseJavaCurve25519Provider {

  private final JCESha512Provider sha512Provider = new JCESha512Provider();

  @Override
  protected Sha512 getSha512() {
    return sha512Provider;
  }

  @Override
  public byte[] getRandom(int length) {
    try {
      byte[]       random       = new byte[length];
      SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
      secureRandom.nextBytes(random);

      return random;
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }
}
