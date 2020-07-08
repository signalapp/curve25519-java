package org.whispersystems.curve25519.java.ed25519;

import static org.whispersystems.curve25519.java.fe_0.fe_0;
import static org.whispersystems.curve25519.java.fe_1.fe_1;
import static org.whispersystems.curve25519.java.fe_cmov.fe_cmov;
import static org.whispersystems.curve25519.java.fe_copy.fe_copy;
import static org.whispersystems.curve25519.java.fe_frombytes.fe_frombytes;
import static org.whispersystems.curve25519.java.fe_mul.fe_mul;
import static org.whispersystems.curve25519.java.fe_pow22523.fe_pow22523;
import static org.whispersystems.curve25519.java.fe_sq.fe_sq;

public class fe_sqrt {

    // sqrt(-1)
    static final byte[] i_bytes = {
            (byte) 0xb0, (byte) 0xa0, (byte) 0x0e, (byte) 0x4a, (byte) 0x27, (byte) 0x1b, (byte) 0xee, (byte) 0xc4,
            (byte) 0x78, (byte) 0xe4, (byte) 0x2f, (byte) 0xad, (byte) 0x06, (byte) 0x18, (byte) 0x43, (byte) 0x2f,
            (byte) 0xa7, (byte) 0xd7, (byte) 0xfb, (byte) 0x3d, (byte) 0x99, (byte) 0x00, (byte) 0x4d, (byte) 0x2b,
            (byte) 0x0b, (byte) 0xdf, (byte) 0xc1, (byte) 0x4f, (byte) 0x80, (byte) 0x24, (byte) 0x83, (byte) 0x2b
    };


    /**
     * calc sqrt(a)
     * @param out
     * @param a
     * @pre a is square or zero
     * @post out^2 = a
     * @return
     */
    static int fe_sqrt(int[] out, int[] a)
    {
        int[] exp = new int[10], b = new int[10], b2 = new int[10], bi = new int[10], i = new int[10];
        int[] legendre = new int[10], zero = new int[10], one = new int[10];

        fe_frombytes(i, i_bytes);
        fe_pow22523(exp, a);

        fe_sq(legendre, exp);
        fe_sq(legendre, legendre);
        fe_mul(legendre, legendre, a);
        fe_mul(legendre, legendre, a);

        fe_0(zero);
        fe_1(one);
        if (fe_isequal.fe_isequal(legendre, zero) == 0 && fe_isequal.fe_isequal(legendre, one) == 0)
            return -1;

        fe_mul(b, a, exp);
        fe_sq(b2, b);

        fe_mul(bi, b, i);
        fe_cmov(b, bi, 1 ^ fe_isequal.fe_isequal(b2, a));
        fe_copy(out, b);


        fe_sq(b2, out);
        if (fe_isequal.fe_isequal(a, b2) == 0)
            return -1;

        return 0;

    }


}
