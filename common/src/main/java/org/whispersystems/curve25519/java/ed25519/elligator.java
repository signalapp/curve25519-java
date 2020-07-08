package org.whispersystems.curve25519.java.ed25519;

import org.whispersystems.curve25519.java.Sha512;
import org.whispersystems.curve25519.java.ge_p3;

import static org.whispersystems.curve25519.java.fe_0.fe_0;
import static org.whispersystems.curve25519.java.fe_1.fe_1;
import static org.whispersystems.curve25519.java.fe_add.fe_add;
import static org.whispersystems.curve25519.java.fe_cmov.fe_cmov;
import static org.whispersystems.curve25519.java.fe_frombytes.fe_frombytes;
import static org.whispersystems.curve25519.java.fe_invert.fe_invert;
import static org.whispersystems.curve25519.java.fe_mul.fe_mul;
import static org.whispersystems.curve25519.java.fe_neg.fe_neg;
import static org.whispersystems.curve25519.java.fe_pow22523.fe_pow22523;
import static org.whispersystems.curve25519.java.fe_sq.fe_sq;
import static org.whispersystems.curve25519.java.fe_sq2.fe_sq2;
import static org.whispersystems.curve25519.java.fe_tobytes.fe_tobytes;

public class elligator {

    /**
     * @param in
     * @return   1 -> square
     *           0 -> 0
     *          -1 -> nonsquare
     */
    static int legendre_is_nonsquare(int[] in)
    {
        int[] temp = new int[10];
        byte[] bytes =  new byte[32];
        fe_pow22523(temp, in);  /* temp = in^((q-5)/8) */
        fe_sq(temp, temp);      /*        in^((q-5)/4) */
        fe_sq(temp, temp);      /*        in^((q-5)/2) */
        fe_mul(temp, temp, in); /*        in^((q-3)/2) */
        fe_mul(temp, temp, in); /*        in^((q-1)/2) */

        fe_tobytes(bytes, temp);
        return 1 & bytes[31];
    }

    /**
     * Elligator2 uniform random bit string
     * @param u
     * @param r
     */

    static void elligator(int[] u, int[] r)
    {
        int[] A = new int[10], one = new int[10], twor2 = new int[10], twor2plus1 = new int[10], twor2plus1inv = new int[10];
        int[] x = new int[10], e = new int[10], Atemp = new int[10], uneg = new int[10];
        int nonsquare;

        fe_1(one);
        fe_0(A);
        A[0] = 486662;

        fe_sq2(twor2, r);
        fe_add(twor2plus1, twor2, one);
        fe_invert(twor2plus1inv, twor2plus1);
        fe_mul(x, twor2plus1inv, A);
        fe_neg(x, x);

        fe_mont_rhs.fe_mont_rhs(e, x);
        nonsquare = legendre_is_nonsquare(e);

        fe_0(Atemp);
        fe_cmov(Atemp, A, nonsquare);
        fe_add(u, x, Atemp);
        fe_neg(uneg, u);
        fe_cmov(u, uneg, nonsquare);
    }

    /**
     * hash byte string to EC25519 Point
     * @param p
     * @param in
     * @param in_len
     * @param sha512provider
     */
    static int hash_to_point(ge_p3 p, byte[] in, long in_len, Sha512 sha512provider)
    {
        byte[] hash = new byte[64];
        int[] h = new int[10], u = new int[10];
        int sign_bit;
        ge_p3 p3 = new ge_p3();

        sha512provider.calculateDigest(hash, in, in_len);

        /* take the high bit as Edwards sign bit */
        sign_bit = (hash[31] & 0x80) >> 7;
        hash[31] &= 0x7F;
        fe_frombytes(h, hash);
        elligator(u, h);

        if (ge_montx_to_p3.ge_montx_to_p3(p3, u, sign_bit) !=0)
            return -1;
        ge_scalarmult_cofactor.ge_scalarmult_cofactor(p, p3);

        return 0;
    }

}
