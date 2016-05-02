/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.curve25519;

/**
 * A tuple that contains a Curve25519 public and private key.
 *
 * @author Moxie Marlinspike
 */
public class Curve25519KeyPair {

  private final byte[] publicKey;
  private final byte[] privateKey;

  Curve25519KeyPair(byte[] publicKey, byte[] privateKey) {
    this.publicKey  = publicKey;
    this.privateKey = privateKey;
  }

  /**
   * @return The Curve25519 public key.
   */
  public byte[] getPublicKey() {
    return publicKey;
  }

  /**
   * @return The Curve25519 private key.
   */
  public byte[] getPrivateKey() {
    return privateKey;
  }
}
