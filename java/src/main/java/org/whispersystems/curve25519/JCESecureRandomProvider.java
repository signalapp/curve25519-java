/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.curve25519;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class JCESecureRandomProvider implements SecureRandomProvider {

  @Override
  public void nextBytes(byte[] output) {
    try {
      SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
      secureRandom.nextBytes(output);
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }

  @Override
  public int nextInt(int maxValue) {
    try {
      SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
      return secureRandom.nextInt(maxValue);
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }
}
