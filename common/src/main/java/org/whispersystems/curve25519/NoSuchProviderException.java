package org.whispersystems.curve25519;

public class NoSuchProviderException extends Exception {
  public NoSuchProviderException(Throwable e) {
    super(e);
  }

  public NoSuchProviderException(String type) {
    super(type);
  }
}
