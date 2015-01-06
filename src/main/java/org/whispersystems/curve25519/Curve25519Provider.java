package org.whispersystems.curve25519;

public interface Curve25519Provider {

  byte[] calculateAgreement(byte[] ourPrivate, byte[] theirPublic);
  byte[] generatePublicKey(byte[] privateKey);
  byte[] generatePrivateKey(byte[] random);

  byte[]  calculateSignature(byte[] random, byte[] privateKey, byte[] message);
  boolean verifySignature(byte[] publicKey, byte[] message, byte[] signature);

}
