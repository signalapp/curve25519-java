package org.whispersystems.curve25519;

import android.test.AndroidTestCase;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class AndroidWrapper extends AndroidTestCase {

  private final NativeCurve25519ProviderTest providerTest = new NativeCurve25519ProviderTest();
  private final NativeCurve25519Test         curveTest    = new NativeCurve25519Test        ();

  public void testEcDh() {
    providerTest.testEcDh();
  }

  public void testKeyGen() {
    providerTest.testKeyGen();
  }

  public void testSignVerify() {
    providerTest.testSignVerify();
  }

  public void testNative() {
    curveTest.testCheckProvider();
  }

  public void testAgreement() {
    curveTest.testAgreement();
  }

  public void testRandomAgreements() throws NoSuchAlgorithmException {
    curveTest.testRandomAgreements();
  }

  public void testSignature() {
    curveTest.testSignature();
  }

  public void testSignatureOverflow() throws InvalidKeyException, NoSuchAlgorithmException {
    curveTest.testSignatureOverflow();
  }
}
