package org.whispersystems.curve25519;

public class J2meCurve25519Test extends Curve25519Test {
  public void testCheckProvider() throws NoSuchProviderException {
    assertFalse(Curve25519.getInstance(getProviderName()).isNative());
  }

  public String getProviderName() {
    return Curve25519.J2ME;
  }

  protected Curve25519 getInstance() throws NoSuchProviderException {
    return Curve25519.getInstance(Curve25519.J2ME, new FakeSecureRandomProvider());
  }
}
