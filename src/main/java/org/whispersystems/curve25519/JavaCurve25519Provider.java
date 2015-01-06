package org.whispersystems.curve25519;

import org.whispersystems.curve25519.java.curve_sigs;
import org.whispersystems.curve25519.java.scalarmult;

class JavaCurve25519Provider implements Curve25519Provider {

  @Override
  public boolean isNative() {
    return false;
  }

  @Override
  public byte[] calculateAgreement(byte[] ourPrivate, byte[] theirPublic) {
    byte[] agreement = new byte[32];
    scalarmult.crypto_scalarmult(agreement, ourPrivate, theirPublic);

    return agreement;
  }

  @Override
  public byte[] generatePublicKey(byte[] privateKey) {
    byte[] publicKey = new byte[32];
    curve_sigs.curve25519_keygen(publicKey, privateKey);

    return publicKey;
  }

  @Override
  public byte[] generatePrivateKey(byte[] random) {
    byte[] privateKey = new byte[32];

    System.arraycopy(random, 0, privateKey, 0, 32);

    privateKey[0]  &= 248;
    privateKey[31] &= 127;
    privateKey[31] |= 64;

    return privateKey;
  }

  @Override
  public byte[] calculateSignature(byte[] random, byte[] privateKey, byte[] message) {
    byte[] result = new byte[64];

    if (curve_sigs.curve25519_sign(result, privateKey, message, message.length, random) != 0) {
      throw new IllegalArgumentException("Message exceeds max length!");
    }

    return result;
  }

  @Override
  public boolean verifySignature(byte[] publicKey, byte[] message, byte[] signature) {
    return curve_sigs.curve25519_verify(signature, publicKey, message, message.length) == 0;
  }
}
