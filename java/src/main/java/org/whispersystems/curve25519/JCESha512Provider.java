/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.curve25519;

import org.whispersystems.curve25519.java.Sha512;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class JCESha512Provider implements Sha512 {
  @Override
  public void calculateDigest(byte[] out, byte[] in, long length) {
    try {
      MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
      messageDigest.update(in, 0, (int)length);
      byte[] digest = messageDigest.digest();
      System.arraycopy(digest, 0, out, 0, digest.length);
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }
}
