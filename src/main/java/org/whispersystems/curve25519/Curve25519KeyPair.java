package org.whispersystems.curve25519;

public class Curve25519KeyPair {

  private final byte[] publicKey;
  private final byte[] privateKey;

  Curve25519KeyPair(byte[] publicKey, byte[] privateKey) {
    this.publicKey  = publicKey;
    this.privateKey = privateKey;
  }

  public byte[] getPublicKey() {
    return publicKey;
  }

  public byte[] getPrivateKey() {
    return privateKey;
  }
}
