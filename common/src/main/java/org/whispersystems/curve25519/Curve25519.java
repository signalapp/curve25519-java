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

/**
 * A Curve25519 interface for generating keys, calculating agreements, creating signatures,
 * and verifying signatures.
 *
 * @author Moxie Marlinspike
 */
public class Curve25519 {

  public static final String NATIVE = "native";
  public static final String JAVA   = "java";
  public static final String J2ME   = "j2me";
  public static final String BEST   = "best";

  public static Curve25519 getInstance(String type) throws NoSuchProviderException {
    if      (NATIVE.equals(type)) return new Curve25519(constructNativeProvider());
    else if (JAVA.equals(type))   return new Curve25519(constructJavaProvider());
    else if (J2ME.equals(type))   return new Curve25519(constructJ2meProvider());
    else if (BEST.equals(type))   return new Curve25519(constructOpportunisticProvider());
    else                          throw new NoSuchProviderException(type);
  }

  private final Curve25519Provider provider;

  private Curve25519(Curve25519Provider provider) {
    this.provider = provider;
  }


//  static {
//    try {
//      provider = new NativeCurve25519Provider();
//    } catch (UnsatisfiedLinkError ule) {
//      provider = new JavaCurve25519Provider();
//    }
//  }

  /**
   * {@link Curve25519} is backed by either a native (via JNI)
   * or pure-Java provider.  By default it prefers the native provider, and falls back to the
   * pure-Java provider if the native library fails to load.
   *
   * @return true if backed by a native provider, false otherwise.
   */
  public boolean isNative() {
    return provider.isNative();
  }

  /**
   * Generates a Curve25519 keypair.
   *
   * @return A randomly generated Curve25519 keypair.
   */
  public Curve25519KeyPair generateKeyPair() {
    byte[] privateKey = provider.generatePrivateKey();
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
  public byte[] calculateAgreement(byte[] publicKey, byte[] privateKey) {
    return provider.calculateAgreement(privateKey, publicKey);
  }

  /**
   * Calculates a Curve25519 signature.
   *
   * @param privateKey The private Curve25519 key to create the signature with.
   * @param message The message to sign.
   * @return A 64-byte signature.
   */
  public byte[] calculateSignature(byte[] privateKey, byte[] message) {
    byte[] random = provider.getRandom(64);
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
  public boolean verifySignature(byte[] publicKey, byte[] message, byte[] signature) {
    return provider.verifySignature(publicKey, message, signature);
  }

//  private byte[] generatePrivateKey() {
//    byte[] privateKey = new byte[32];
//    random.nextBytes(privateKey);
//
//    return provider.generatePrivateKey(privateKey);
//  }

//  private byte[] getRandom(SecureRandom secureRandom, int size) {
//    byte[] output = new byte[size];
//    secureRandom.nextBytes(output);
//
//    return output;
//  }

  private static Curve25519Provider constructNativeProvider() throws NoSuchProviderException {
    return constructClass("NativeCurve25519Provider");
  }

  private static Curve25519Provider constructJavaProvider() throws NoSuchProviderException {
    return constructClass("JavaCurve25519Provider");
  }

  private static Curve25519Provider constructJ2meProvider() throws NoSuchProviderException {
    return constructClass("J2meCurve25519Provider");
  }

  private static Curve25519Provider constructOpportunisticProvider() throws NoSuchProviderException {
    return constructClass("OpportunisticCurve25519Provider");
  }

  private static Curve25519Provider constructClass(String name) throws NoSuchProviderException {
    try {
      return (Curve25519Provider)Class.forName("org.whispersystems.curve25519." + name).newInstance();
    } catch (InstantiationException e) {
      throw new NoSuchProviderException(e);
    } catch (IllegalAccessException e) {
      throw new NoSuchProviderException(e);
    } catch (ClassNotFoundException e) {
      throw new NoSuchProviderException(e);
    }
  }

}
