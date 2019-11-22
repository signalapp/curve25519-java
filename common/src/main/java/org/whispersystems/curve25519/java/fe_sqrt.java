package org.whispersystems.curve25519.java;

public class fe_sqrt {

    /* sqrt(-1) */
    public static byte[] i_bytes = {
            (byte)0xb0, (byte)0xa0, 0x0e, 0x4a, 0x27, 0x1b, (byte)0xee, (byte)0xc4,
                0x78, (byte)0xe4, 0x2f, (byte)0xad, 0x06, 0x18, 0x43, 0x2f,
            (byte)0xa7, (byte)0xd7, (byte)0xfb, 0x3d, (byte)0x99, 0x00, 0x4d, 0x2b,
                0x0b, (byte)0xdf, (byte)0xc1, 0x4f, (byte)0x80, 0x24, (byte)0x83, 0x2b
    };

    /* Preconditions: a is square or zero */

    public static void fe_sqrt(int[] out, int[] a)
    {
        int[] exp = new int[10], b = new int[10], b2 = new int[10], bi = new int[10], i = new int[10];

        fe_frombytes.fe_frombytes(i, i_bytes);
        fe_pow22523.fe_pow22523(exp, a);             /* b = a^(q-5)/8        */


        fe_mul.fe_mul(b, a, exp);       /* b = a * a^(q-5)/8    */
        fe_sq.fe_sq(b2, b);            /* b^2 = a * a^(q-1)/4  */

        /* note b^4 == a^2, so b^2 == a or -a
         * if b^2 != a, multiply it by sqrt(-1) */
        fe_mul.fe_mul(bi, b, i);
        fe_cmov.fe_cmov(b, bi, 1 ^ fe_isequal.fe_isequal(b2, a));
        fe_copy.fe_copy(out, b);

    }

}
