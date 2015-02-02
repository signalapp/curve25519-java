package org.whispersystems.curve25519;

public class J2meCurve25519ProviderTest extends Curve25519ProviderTest {
  protected Curve25519Provider createProvider() throws NoSuchProviderException {
    J2meCurve25519Provider provider = new J2meCurve25519Provider();
    provider.setRandomProvider(new FakeSecureRandomProvider());
    return provider;
  }
}
