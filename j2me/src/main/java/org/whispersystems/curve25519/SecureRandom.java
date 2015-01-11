package org.whispersystems.curve25519;

public class SecureRandom {

  private static final SecureRandom secureRandom = new SecureRandom();

  public static SecureRandom getInstance() {
    return secureRandom;
  }

  public void nextBytes(byte[] bytes) {
    // Placeholder
  }
}
