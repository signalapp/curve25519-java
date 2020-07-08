package org.whispersystems.curve25519.java.ed25519;

public class point_isreduced {

    static boolean point_isreduced(byte[] p)
    {
        byte[] strict =  new byte[32];

        System.arraycopy(p, 0, strict, 0, 32);
        strict[31] &= 0x7F; /* mask off sign bit */
        return fe_isreduced.fe_isreduced(strict);
    }


}
