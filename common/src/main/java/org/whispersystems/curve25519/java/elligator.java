package org.whispersystems.curve25519.java;

public class elligator {
    public static int legendre_is_nonsquare(int[] in)
    {
        int[] temp = new int[10];
        byte[] bytes = new byte[32];
        fe_pow22523.fe_pow22523(temp, in);  /* temp = in^((q-5)/8) */
        fe_sq.fe_sq(temp, temp);      /*        in^((q-5)/4) */
        fe_sq.fe_sq(temp, temp);      /*        in^((q-5)/2) */
        fe_mul.fe_mul(temp, temp, in); /*        in^((q-3)/2) */
        fe_mul.fe_mul(temp, temp, in); /*        in^((q-1)/2) */

        /* temp is now the Legendre symbol:
         * 1  = square
         * 0  = input is zero
         * -1 = nonsquare
         */
        fe_tobytes.fe_tobytes(bytes, temp);
        return 1 & bytes[31];
    }

    public static void elligator(int[] u, int[] r)
    {
        /* r = input
         * gen_x = -A/(1+2r^2)                # 2 is nonsquare
         * e = (gen_x^3 + Ax^2 + gen_x)^((q-1)/2) # legendre symbol
         * if e == 1 (square) or e == 0 (because gen_x == 0 and 2r^2 + 1 == 0)
         *   u = gen_x
         * if e == -1 (nonsquare)
         *   u = -gen_x - A
         */
        int[] A = new int[10], one = new int[10], twor2 = new int[10], twor2plus1 = new int[10], twor2plus1inv = new int[10];
        int[] x = new int[10], e = new int[10], Atemp = new int[10], uneg = new int[10];
        int nonsquare;

        fe_1.fe_1(one);
        fe_0.fe_0(A);
        A[0] = 486662;                         /* A = 486662 */

        fe_sq2.fe_sq2(twor2, r);                      /* 2r^2 */
        fe_add.fe_add(twor2plus1, twor2, one);        /* 1+2r^2 */
        fe_invert.fe_invert(twor2plus1inv, twor2plus1);  /* 1/(1+2r^2) */
        fe_mul.fe_mul(x, twor2plus1inv, A);           /* A/(1+2r^2) */
        fe_neg.fe_neg(x, x);                          /* gen_x = -A/(1+2r^2) */

        fe_mont_rhs.fe_mont_rhs(e, x);                     /* e = gen_x^3 + Ax^2 + gen_x */
        nonsquare = legendre_is_nonsquare(e);

        fe_0.fe_0(Atemp);
        fe_cmov.fe_cmov(Atemp, A, nonsquare);          /* 0, or A if nonsquare */
        fe_add.fe_add(u, x, Atemp);                   /* gen_x, or gen_x+A if nonsquare */
        fe_neg.fe_neg(uneg, u);                       /* -gen_x, or -gen_x-A if nonsquare */
        fe_cmov.fe_cmov(u, uneg, nonsquare);           /* gen_x, or -gen_x-A if nonsquare */
    }

    public static void hash_to_point(Sha512 sha512provider, ge_p3 p, byte[] in)
    {
        byte[] hash = new byte[64];
        int[] h = new int[10], u = new int[10];
        ge_p3 p3 = new ge_p3();

        sha512provider.calculateDigest(hash, in, in.length);

        /* take the high bit as Edwards sign bit */
        byte sign_bit = (byte)((hash[31] & 0x80) >> 7);
        hash[31] &= 0x7F;
        fe_frombytes.fe_frombytes(h, hash);
        elligator(u, h);

        ge_montx_to_p3.ge_montx_to_p3(p3, u, sign_bit);
        ge_scalarmult_cofactor.ge_scalarmult_cofactor(p, p3);
    }
}
