package org.whispersystems.curve25519;

public class VrfSignatureVerificationFailedException extends Exception {

  public VrfSignatureVerificationFailedException() {
    super();
  }

  public VrfSignatureVerificationFailedException(String message) {
    super(message);
  }

  public VrfSignatureVerificationFailedException(Exception exception) {
    super(exception);
  }
}
