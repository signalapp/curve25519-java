/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.curve25519;

public interface SecureRandomProvider {
  public void nextBytes(byte[] output);
  public int nextInt(int maxValue);
}
