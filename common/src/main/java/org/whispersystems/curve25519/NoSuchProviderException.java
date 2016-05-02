/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.curve25519;

public class NoSuchProviderException extends RuntimeException {

  private final Throwable nested;

  public NoSuchProviderException(Throwable e) {
    this.nested = e;
  }

  public NoSuchProviderException(String type) {
    super(type);
    this.nested = null;
  }

  public Throwable getNested() {
    return nested;
  }
}
