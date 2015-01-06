package org.whispersystems.curve25519;

public class JavaCurve25519ProviderTest extends Curve25519ProviderTest {
  @Override
  protected Curve25519Provider createProvider() {
    return new JavaCurve25519Provider();
  }
}
