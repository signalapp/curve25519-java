package org.whispersystems.curve25519.java.ed25519;

import static org.whispersystems.curve25519.java.crypto_verify_32.crypto_verify_32;
import static org.whispersystems.curve25519.java.fe_frombytes.fe_frombytes;
import static org.whispersystems.curve25519.java.fe_tobytes.fe_tobytes;

public class fe_isreduced {

    /**
     *
     * @param s
     * @return true if fe_isrecuded
     *         false otherwise
     */
    static boolean fe_isreduced(byte[] s){
        int[] f = new int[10];
        byte[] strict = new byte[32];

        fe_frombytes(f, s);
        fe_tobytes(strict, f);
        if (crypto_verify_32(strict, s) != 0)
            return false;
        return true;
    }
}
