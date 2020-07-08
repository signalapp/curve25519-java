package org.whispersystems.curve25519.java.ed25519;

public class sc_cmov {

    static void sc_cmov(byte[] f, byte[] g, int b)
    {
        int count=32;
        byte[] x =  new byte[32];
        for (count=0; count < 32; count++)
            x[count] = (byte) (f[count] ^ g[count]);
        b = -b;
        for (count=0; count < 32; count++)
            x[count] &= b;
        for (count=0; count < 32; count++)
            f[count] = (byte) (f[count] ^ x[count]);
    }
}
