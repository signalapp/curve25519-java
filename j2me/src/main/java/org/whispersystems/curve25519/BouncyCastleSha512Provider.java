/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.curve25519;

import org.bouncycastle.crypto.digests.SHA512Digest;
import org.whispersystems.curve25519.java.Sha512;

public class BouncyCastleSha512Provider implements Sha512 {
  //@Override
  public void calculateDigest(byte[] out, byte[] in, long length) {
    SHA512Digest digest = new SHA512Digest();
    digest.update(in, 0, (int)length);
    digest.doFinal(out, 0);
  }
}
