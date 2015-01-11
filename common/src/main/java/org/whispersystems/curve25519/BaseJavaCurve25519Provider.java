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

import org.whispersystems.curve25519.java.Sha512;
import org.whispersystems.curve25519.java.curve_sigs;
import org.whispersystems.curve25519.java.scalarmult;

abstract class BaseJavaCurve25519Provider implements Curve25519Provider {

  // @Override
  public boolean isNative() {
    return false;
  }

  // @Override
  public byte[] calculateAgreement(byte[] ourPrivate, byte[] theirPublic) {
    byte[] agreement = new byte[32];
    scalarmult.crypto_scalarmult(agreement, ourPrivate, theirPublic);

    return agreement;
  }

  // @Override
  public byte[] generatePublicKey(byte[] privateKey) {
    byte[] publicKey = new byte[32];
    curve_sigs.curve25519_keygen(publicKey, privateKey);

    return publicKey;
  }

  //  @Override
  public byte[] generatePrivateKey() {
    byte[] random = getRandom(PRIVATE_KEY_LEN);
    return generatePrivateKey(random);
  }

  // @Override
  public byte[] generatePrivateKey(byte[] random) {
    byte[] privateKey = new byte[32];

    System.arraycopy(random, 0, privateKey, 0, 32);

    privateKey[0]  &= 248;
    privateKey[31] &= 127;
    privateKey[31] |= 64;

    return privateKey;
  }

  // @Override
  public byte[] calculateSignature(byte[] random, byte[] privateKey, byte[] message) {
    byte[] result = new byte[64];

    if (curve_sigs.curve25519_sign(getSha512(), result, privateKey, message, message.length, random) != 0) {
      throw new IllegalArgumentException("Message exceeds max length!");
    }

    return result;
  }

  // @Override
  public boolean verifySignature(byte[] publicKey, byte[] message, byte[] signature) {
    return curve_sigs.curve25519_verify(getSha512(), signature, publicKey, message, message.length) == 0;
  }

  protected abstract Sha512 getSha512();

}
