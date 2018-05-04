/*
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.curve25519;

import java.security.SecureRandom;

public class JCESecureRandomProvider implements SecureRandomProvider {

  @Override
  public void nextBytes(byte[] output) {
    new SecureRandom().nextBytes(output);
  }

  @Override
  public int nextInt(int maxValue) {
    return new SecureRandom().nextInt(maxValue);
  }
}
