package org.whispersystems.curve25519.java;

public class ge_montx_to_p3 {
    /* sqrt(-(A+2)) */
    private static byte[] A_bytes = {
            0x06, 0x7e, 0x45, (byte)0xff, (byte)0xaa, 0x04, 0x6e, (byte)0xcc,
            (byte)0x82, 0x1a, 0x7d, 0x4b, (byte)0xd1, (byte)0xd3, (byte)0xa1, (byte)0xc5,
            0x7e, 0x4f, (byte)0xfc, 0x03, (byte)0xdc, 0x08, 0x7b, (byte)0xd2,
            (byte)0xbb, 0x06, (byte)0xa0, 0x60, (byte)0xf4, (byte)0xed, 0x26, 0x0f
    };

    public static void ge_montx_to_p3(ge_p3 p, int[] u, byte ed_sign_bit)
    {
        int[] x = new int[10], y = new int[10], A = new int[10], v = new int[10], v2 = new int[10], iv = new int[10], nx = new int[10];

        fe_frombytes.fe_frombytes(A, A_bytes);

        /* given u, recover edwards y */
        /* given u, recover v */
        /* given u and v, recover edwards gen_x */

        fe_montx_to_edy.fe_montx_to_edy(y, u);       /* y = (u - 1) / (u + 1) */

        fe_mont_rhs.fe_mont_rhs(v2, u);          /* v^2 = u(u^2 + Au + 1) */
        fe_sqrt.fe_sqrt(v, v2);              /* v = sqrt(v^2) */

        fe_mul.fe_mul(x, u, A);             /* gen_x = u * sqrt(-(A+2)) */
        fe_invert.fe_invert(iv, v);            /* 1/v */
        fe_mul.fe_mul(x, x, iv);            /* gen_x = (u/v) * sqrt(-(A+2)) */

        fe_neg.fe_neg(nx, x);               /* negate gen_x to match sign bit */
        fe_cmov.fe_cmov(x, nx, fe_isnegative.fe_isnegative(x) ^ ed_sign_bit);

        fe_copy.fe_copy(p.X, x);
        fe_copy.fe_copy(p.Y, y);
        fe_1.fe_1(p.Z);
        fe_mul.fe_mul(p.T, p.X, p.Y);
    }
}
