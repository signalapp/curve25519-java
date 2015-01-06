package org.whispersystems.curve25519;

import java.security.SecureRandom;

public class Curve25519 {

  private static Curve25519Provider provider;

  static {
    try {
      provider = new NativeCurve25519Provider();
    } catch (UnsatisfiedLinkError ule) {
      provider = new JavaCurve25519Provider();
    }
  }

  public static boolean isNative() {
    return provider.isNative();
  }

  public static Curve25519KeyPair generateKeyPair(SecureRandom secureRandom) {
    byte[] privateKey = generatePrivateKey(secureRandom);
    byte[] publicKey  = provider.generatePublicKey(privateKey);

    return new Curve25519KeyPair(publicKey, privateKey);
  }

  public static byte[] calculateAgreement(byte[] publicKey, byte[] privateKey) {
    return provider.calculateAgreement(privateKey, publicKey);
  }

  public static byte[] calculateSignature(SecureRandom secureRandom, byte[] privateKey, byte[] message) {
    byte[] random = getRandom(secureRandom, 64);
    return provider.calculateSignature(random, privateKey, message);
  }

  public static boolean verifySignature(byte[] publicKey, byte[] message, byte[] signature) {
    return provider.verifySignature(publicKey, message, signature);
  }

  private static byte[] generatePrivateKey(SecureRandom random) {
    byte[] privateKey = new byte[32];
    random.nextBytes(privateKey);

    return provider.generatePrivateKey(privateKey);
  }

  private static byte[] getRandom(SecureRandom secureRandom, int size) {
    byte[] output = new byte[size];
    secureRandom.nextBytes(output);

    return output;
  }


}
