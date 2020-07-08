package org.whispersystems.curve25519.java.ed25519;

import static org.whispersystems.curve25519.java.fe_1.fe_1;
import static org.whispersystems.curve25519.java.fe_add.fe_add;
import static org.whispersystems.curve25519.java.fe_invert.fe_invert;
import static org.whispersystems.curve25519.java.fe_mul.fe_mul;
import static org.whispersystems.curve25519.java.fe_sub.fe_sub;

public class fe_montx_to_edy {

    /**
     * y = (u - 1) / (u + 1)
     * @param y
     * @param u
     */
    static void fe_montx_to_edy(int[] y, int[] u)
    {

        int[] one = new int[10], um1 = new int[10], up1 = new int[10];

        fe_1(one);
        fe_sub(um1, u, one);
        fe_add(up1, u, one);
        fe_invert(up1, up1);
        fe_mul(y, um1, up1);
    }

}
