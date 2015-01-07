package org.whispersystems.curve25519;

class NativeCurve25519Provider implements Curve25519Provider {

  static {
    System.loadLibrary("curve25519");
  }

  @Override
  public boolean isNative() {
    return true;
  }

  @Override
  public native byte[] calculateAgreement(byte[] ourPrivate, byte[] theirPublic);

  @Override
  public native byte[] generatePublicKey(byte[] privateKey);

  @Override
  public native byte[] generatePrivateKey(byte[] random);

  @Override
  public native byte[] calculateSignature(byte[] random, byte[] privateKey, byte[] message);

  @Override
  public native boolean verifySignature(byte[] publicKey, byte[] message, byte[] signature);

}
