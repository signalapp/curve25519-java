package org.whispersystems.curve25519.java.ed25519;

import static org.whispersystems.curve25519.java.sc_muladd.sc_muladd;

public class sc_neg {


    static final byte[] lminus1 = {
            (byte) 0xec, (byte) 0xd3, (byte) 0xf5, (byte) 0x5c, (byte) 0x1a, (byte) 0x63, (byte) 0x12, (byte) 0x58,
            (byte) 0xd6, (byte) 0x9c, (byte) 0xf7, (byte) 0xa2, (byte) 0xde, (byte) 0xf9, (byte) 0xde, (byte) 0x14,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x10};

    /**
     * b =  -a (mod 1)
     * @param b
     * @param a
     */
    static void sc_neg(byte[] b, byte[] a)
    {
        byte[] zero = new byte[32];
        sc_muladd(b, lminus1, a, zero);
    }
}
