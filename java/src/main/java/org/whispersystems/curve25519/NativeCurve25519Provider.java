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

class NativeCurve25519Provider implements Curve25519Provider {

  private static boolean   libraryPresent         = false;
  private static Throwable libraryFailedException = null;

  static {
    try {
      System.loadLibrary("curve25519");
      libraryPresent = true;
    } catch (UnsatisfiedLinkError | SecurityException e) {
      libraryPresent         = false;
      libraryFailedException = e;
    }
  }

  private SecureRandomProvider secureRandomProvider = new JCESecureRandomProvider();

  NativeCurve25519Provider() throws NoSuchProviderException {
    if (!libraryPresent) throw new NoSuchProviderException(libraryFailedException);

    try {
      smokeCheck(31337);
    } catch (UnsatisfiedLinkError ule) {
      throw new NoSuchProviderException(ule);
    }
  }

  @Override
  public boolean isNative() {
    return true;
  }

  @Override
  public byte[] generatePrivateKey() {
    byte[] random = getRandom(PRIVATE_KEY_LEN);
    return generatePrivateKey(random);
  }

  @Override
  public byte[] getRandom(int length) {
    byte[] result = new byte[length];
    secureRandomProvider.nextBytes(result);

    return result;
  }

  @Override
  public void setRandomProvider(SecureRandomProvider provider) {
    this.secureRandomProvider = provider;
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

  private native boolean smokeCheck(int dummy);

}
