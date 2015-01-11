package org.whispersystems.curve25519;

public class NativeCurve25519Test extends Curve25519Test {

  @Override
  public void testCheckProvider() throws NoSuchProviderException {
    assertTrue(Curve25519.getInstance(getProviderName()).isNative());
  }

  @Override
  public String getProviderName() {
    return "native";
  }

}
