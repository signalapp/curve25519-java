package org.whispersystems.curve25519.java;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class crypto_hash_sha512 {

    public static void crypto_hash_sha512(byte[] out, byte[] in, long len) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            md.update(in, 0, (int)len);
            byte[] mdbytes = md.digest();
            System.arraycopy(mdbytes, 0, out, 0, 64);
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }
}
