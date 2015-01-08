/**
 * Copyright (C) 2015 Open Whisper Systems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.whispersystems.curve25519;

import java.security.SecureRandom;

/**
 * A Curve25519 interface for generating keys, calculating agreements, creating signatures,
 * and verifying signatures.
 *
 * @author Moxie Marlinspike
 */
public class Curve25519 {

  private static Curve25519Provider provider;

  static {
    try {
      provider = new NativeCurve25519Provider();
    } catch (UnsatisfiedLinkError ule) {
      provider = new JavaCurve25519Provider();
    }
  }

  /**
   * {@link Curve25519} is backed by either a native (via JNI)
   * or pure-Java provider.  By default it prefers the native provider, and falls back to the
   * pure-Java provider if the native library fails to load.
   *
   * @return true if backed by a native provider, false otherwise.
   */
  public static boolean isNative() {
    return provider.isNative();
  }

  /**
   * Generates a Curve25519 keypair.
   *
   * @param secureRandom The {@link java.security.SecureRandom} instace to use
   *                     for generating the private key material.
   * @return A randomly generated Curve25519 keypair.
   */
  public static Curve25519KeyPair generateKeyPair(SecureRandom secureRandom) {
    byte[] privateKey = generatePrivateKey(secureRandom);
    byte[] publicKey  = provider.generatePublicKey(privateKey);

    return new Curve25519KeyPair(publicKey, privateKey);
  }

  /**
   * Calculates an ECDH agreement.
   *
   * @param publicKey The Curve25519 (typically remote party's) public key.
   * @param privateKey The Curve25519 (typically yours) private key.
   * @return A 32-byte shared secret.
   */
  public static byte[] calculateAgreement(byte[] publicKey, byte[] privateKey) {
    return provider.calculateAgreement(privateKey, publicKey);
  }

  /**
   * Calculates a Curve25519 signature.
   *
   * @param secureRandom The {@link java.security.SecureRandom} instance to use for deriving
   *                     a Schnorr nonce.
   * @param privateKey The private Curve25519 key to create the signature with.
   * @param message The message to sign.
   * @return A 64-byte signature.
   */
  public static byte[] calculateSignature(SecureRandom secureRandom, byte[] privateKey, byte[] message) {
    byte[] random = getRandom(secureRandom, 64);
    return provider.calculateSignature(random, privateKey, message);
  }

  /**
   * Verify a Curve25519 signature.
   *
   * @param publicKey The Curve25519 public key the signature belongs to.
   * @param message The message that was signed.
   * @param signature The signature to verify.
   * @return true if valid, false if not.
   */
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
