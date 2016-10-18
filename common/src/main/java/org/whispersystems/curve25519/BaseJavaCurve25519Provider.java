/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.curve25519;

import org.whispersystems.curve25519.java.Sha512;
import org.whispersystems.curve25519.java.curve_sigs;
import org.whispersystems.curve25519.java.scalarmult;

abstract class BaseJavaCurve25519Provider implements Curve25519Provider {

  private final Sha512               sha512provider;
  private       SecureRandomProvider secureRandomProvider;

  protected BaseJavaCurve25519Provider(Sha512 sha512provider,
                                       SecureRandomProvider secureRandomProvider)
  {
    this.sha512provider       = sha512provider;
    this.secureRandomProvider = secureRandomProvider;
  }

  public abstract boolean isNative();

  public void setRandomProvider(SecureRandomProvider secureRandomProvider) {
    this.secureRandomProvider = secureRandomProvider;
  }

  public byte[] calculateAgreement(byte[] ourPrivate, byte[] theirPublic) {
    byte[] agreement = new byte[32];
    scalarmult.crypto_scalarmult(agreement, ourPrivate, theirPublic);

    return agreement;
  }

  public byte[] generatePublicKey(byte[] privateKey) {
    byte[] publicKey = new byte[32];
    curve_sigs.curve25519_keygen(publicKey, privateKey);

    return publicKey;
  }

  public byte[] generatePrivateKey() {
    byte[] random = getRandom(PRIVATE_KEY_LEN);
    return generatePrivateKey(random);
  }

  public byte[] generatePrivateKey(byte[] random) {
    byte[] privateKey = new byte[32];

    System.arraycopy(random, 0, privateKey, 0, 32);

    privateKey[0]  &= 248;
    privateKey[31] &= 127;
    privateKey[31] |= 64;

    return privateKey;
  }

  public byte[] calculateSignature(byte[] random, byte[] privateKey, byte[] message) {
    byte[] result = new byte[64];

    if (curve_sigs.curve25519_sign(sha512provider, result, privateKey, message, message.length, random) != 0) {
      throw new IllegalArgumentException("Message exceeds max length!");
    }

    return result;
  }

  public boolean verifySignature(byte[] publicKey, byte[] message, byte[] signature) {
    return curve_sigs.curve25519_verify(sha512provider, signature, publicKey, message, message.length) == 0;
  }

  public byte[] calculateVrfSignature(byte[] random, byte[] privateKey, byte[] message) {
    throw new AssertionError("NYI");
  }

  public byte[] verifyVrfSignature(byte[] publicKey, byte[] message, byte[] signature)
      throws VrfSignatureVerificationFailedException
  {
    throw new AssertionError("NYI");
  }

  public byte[] getRandom(int length) {
    byte[] result = new byte[length];
    secureRandomProvider.nextBytes(result);
    return result;
  }
}
