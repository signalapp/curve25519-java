package org.whispersystems.curve25519;

import org.whispersystems.curve25519.java.Sha512;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class JavaCurve25519Provider extends BaseJavaCurve25519Provider {

  protected JavaCurve25519Provider() {
    super(new JCESha512Provider(), new JCESecureRandomProvider());
  }

  @Override
  public boolean isNative() {
    return false;
  }

}
