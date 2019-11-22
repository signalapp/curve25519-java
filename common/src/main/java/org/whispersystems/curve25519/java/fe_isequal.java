package org.whispersystems.curve25519.java;

public class fe_isequal {
    /*
    return 1 if f == g
    return 0 if f != g
    */
    public static int fe_isequal(int[] f, int[] g)
    {
        int[] h = new int[10];
        fe_sub.fe_sub(h, f, g);
        return 1 & (((fe_isnonzero.fe_isnonzero(h) & 0xff) - 1) >> 8);
    }

}
