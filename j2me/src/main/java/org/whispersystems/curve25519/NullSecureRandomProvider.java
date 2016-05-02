/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.curve25519;

public class NullSecureRandomProvider implements SecureRandomProvider {
//  @Override
  public void nextBytes(byte[] output) {
    throw new IllegalArgumentException("No default J2ME Secure Random provider available!");
  }

//  @Override
  public int nextInt(int maxValue) {
    throw new IllegalArgumentException("No default J2ME Secure Random provider available!");
  }
}
