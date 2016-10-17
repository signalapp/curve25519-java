package org.whispersystems.curve25519;

public class UniqueSignatureVerificationFailedException extends Exception {

  public UniqueSignatureVerificationFailedException() {
    super();
  }

  public UniqueSignatureVerificationFailedException(String message) {
    super(message);
  }

  public UniqueSignatureVerificationFailedException(Exception exception) {
    super(exception);
  }
}
