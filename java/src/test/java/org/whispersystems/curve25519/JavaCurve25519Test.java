package org.whispersystems.curve25519;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class JavaCurve25519Test extends Curve25519Test {
  @Override
  public void testCheckProvider() throws NoSuchProviderException {
    assertFalse(Curve25519.getInstance(getProviderName()).isNative());
  }

  @Override
  public String getProviderName() {
    return Curve25519.JAVA;
  }
}
