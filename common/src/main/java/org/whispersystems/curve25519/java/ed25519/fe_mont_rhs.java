package org.whispersystems.curve25519.java.ed25519;

import static org.whispersystems.curve25519.java.fe_0.fe_0;
import static org.whispersystems.curve25519.java.fe_1.fe_1;
import static org.whispersystems.curve25519.java.fe_add.fe_add;
import static org.whispersystems.curve25519.java.fe_mul.fe_mul;
import static org.whispersystems.curve25519.java.fe_sq.fe_sq;

public class fe_mont_rhs {

    static void fe_mont_rhs(int[] v2, int[] u) {
        int[] A = new int[10], one = new int[10];
        int[] u2 = new int[10], Au = new int[10], inner = new int[10];

        fe_1(one);
        fe_0(A);
        A[0] = 486662;

        fe_sq(u2, u);
        fe_mul(Au, A, u);
        fe_add(inner, u2, Au);
        fe_add(inner, inner, one);
        fe_mul(v2, u, inner);
    }

}
