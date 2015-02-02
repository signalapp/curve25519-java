package org.whispersystems.curve25519;

public class NullSecureRandomProvider implements SecureRandomProvider {
  @Override
  public void nextBytes(byte[] output) {
    throw new IllegalArgumentException("No default J2ME Secure Random provider available!");
  }
}
