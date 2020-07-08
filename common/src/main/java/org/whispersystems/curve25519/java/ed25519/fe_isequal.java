package org.whispersystems.curve25519.java.ed25519;

import static org.whispersystems.curve25519.java.fe_isnonzero.fe_isnonzero;
import static org.whispersystems.curve25519.java.fe_sub.fe_sub;

public class fe_isequal {

    /**
     *
     * @param f
     * @param g
     * @return 1 if f==g
     *         0 if f!= g
     */

    static int fe_isequal(int[] f, int[] g)
    {
        int[] h = new int[10];
        fe_sub(h, f, g);
        return (1 ^ (1 & (fe_isnonzero(h) >> 8)));
    }
}
