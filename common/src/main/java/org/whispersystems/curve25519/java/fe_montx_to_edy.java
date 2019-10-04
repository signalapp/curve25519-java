package org.whispersystems.curve25519.java;

public class fe_montx_to_edy {
    public static void fe_montx_to_edy(int[] y, int[] u)
    {
      /*
         y = (u - 1) / (u + 1)

         NOTE: u=-1 is converted to y=0 since fe_invert is mod-exp
      */
        int[] one = new int[10], um1 = new int[10], up1 = new int[10];

        fe_1.fe_1(one);
        fe_sub.fe_sub(um1, u, one);
        fe_add.fe_add(up1, u, one);
        fe_invert.fe_invert(up1, up1);
        fe_mul.fe_mul(y, um1, up1);
    }

}
