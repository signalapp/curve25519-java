package org.whispersystems.curve25519.java;

public class sc_cmov {
    /*
    Replace (f,g) with (g,g) if b == 1;
    replace (f,g) with (f,g) if b == 0.

    Preconditions: b in {0,1}.
    */

    public static void sc_cmov(byte[] f, byte[] g, byte b) {
        int count = 32;
        byte[] x = new byte[32];
        for (count = 0; count < 32; count++)
            x[count] = (byte) (f[count] ^ g[count]);
        b = (byte)-b;
        for (count = 0; count < 32; count++)
            x[count] &= b;
        for (count = 0; count < 32; count++)
            f[count] = (byte) (f[count] ^ x[count]);
    }
}
