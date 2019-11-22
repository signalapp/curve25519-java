package org.whispersystems.curve25519.java;

public class fe_isreduced {
    public static boolean fe_isreduced(byte[] s)
    {
        int[] f = new int[10];
        byte[] strict = new byte[32];

        fe_frombytes.fe_frombytes(f, s);
        fe_tobytes.fe_tobytes(strict, f);
        return crypto_verify_32.crypto_verify_32(strict, s) == 0;
    }

}
