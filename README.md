
API
----
 * javasrc.scalarmult.crypto_scalarmult()  # ECDH or key generation

 * javasrc.curve_sigs.curve25519_keygen()  # Faster key generation

 * javasrc.curve_sigs.curve25519_sign()

 * javasrc.curve_sigs.curve25519_verify()

Testing
--------
Run 'make java' and 'make test' to build and test the java.

Porting
--------
Run 'make convert' to convert c files in ref10_extract/ into java in generated/.

After some manual fixup, the files are placed in javasrc/.

