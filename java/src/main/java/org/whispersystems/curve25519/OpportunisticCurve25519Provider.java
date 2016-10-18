/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.curve25519;

public class OpportunisticCurve25519Provider implements Curve25519Provider {

  private Curve25519Provider delegate;

  OpportunisticCurve25519Provider() {
    try {
      delegate = new NativeCurve25519Provider();
    } catch (NoSuchProviderException e) {
      delegate = new JavaCurve25519Provider();
    }
  }

  @Override
  public boolean isNative() {
    return delegate.isNative();
  }

  @Override
  public byte[] calculateAgreement(byte[] ourPrivate, byte[] theirPublic) {
    return delegate.calculateAgreement(ourPrivate, theirPublic);
  }

  @Override
  public byte[] generatePublicKey(byte[] privateKey) {
    return delegate.generatePublicKey(privateKey);
  }

  @Override
  public byte[] generatePrivateKey() {
    return delegate.generatePrivateKey();
  }

  @Override
  public byte[] generatePrivateKey(byte[] random) {
    return delegate.generatePrivateKey(random);
  }

  @Override
  public byte[] getRandom(int length) {
    return delegate.getRandom(length);
  }

  @Override
  public void setRandomProvider(SecureRandomProvider provider) {
    delegate.setRandomProvider(provider);
  }

  @Override
  public byte[] calculateSignature(byte[] random, byte[] privateKey, byte[] message) {
    return delegate.calculateSignature(random, privateKey, message);
  }

  @Override
  public boolean verifySignature(byte[] publicKey, byte[] message, byte[] signature) {
    return delegate.verifySignature(publicKey, message, signature);
  }

  @Override
  public byte[] calculateVrfSignature(byte[] random, byte[] privateKey, byte[] message) {
    return delegate.calculateVrfSignature(random, privateKey, message);
  }

  @Override
  public byte[] verifyVrfSignature(byte[] publicKey, byte[] message, byte[] signature)
      throws VrfSignatureVerificationFailedException
  {
    return delegate.verifyVrfSignature(publicKey, message, signature);
  }

}
