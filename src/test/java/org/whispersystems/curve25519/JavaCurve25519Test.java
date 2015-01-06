package org.whispersystems.curve25519;

import static junit.framework.TestCase.assertFalse;

public class JavaCurve25519Test extends Curve25519Test {
  @Override
  public void testCheckProvider() {
    assertFalse(Curve25519.isNative());
  }
}
