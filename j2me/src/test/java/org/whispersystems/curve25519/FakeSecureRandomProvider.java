package org.whispersystems.curve25519;

public class FakeSecureRandomProvider implements SecureRandomProvider {
  public void nextBytes(byte[] output) {

  }

  public int nextInt(int maxValue) {
    return maxValue;
  }
}
