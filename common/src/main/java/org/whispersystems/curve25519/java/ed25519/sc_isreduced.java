package org.whispersystems.curve25519.java.ed25519;

import static org.whispersystems.curve25519.java.crypto_verify_32.crypto_verify_32;
import static org.whispersystems.curve25519.java.sc_reduce.sc_reduce;

public class sc_isreduced {

    static boolean sc_isreduced(byte[] s)
    {
        byte[] strict = new byte[64];

        System.arraycopy(s, 0, strict, 0, 32);

        sc_reduce(strict);
        if (crypto_verify_32(strict, s) != 0)
            return false;
        return true;
    }
}
