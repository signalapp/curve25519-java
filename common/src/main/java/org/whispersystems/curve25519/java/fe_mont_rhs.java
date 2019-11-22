package org.whispersystems.curve25519.java;

public class fe_mont_rhs {
    public static void fe_mont_rhs(int[] v2, int[] u) {
        int[] A = new int[10], one= new int[10];
        int[] u2= new int[10], Au= new int[10], inner= new int[10];

        fe_1.fe_1(one);
        fe_0.fe_0(A);
        A[0] = 486662;                     /* A = 486662 */

        fe_sq.fe_sq(u2, u);                      /* u^2 */
        fe_mul.fe_mul(Au, A, u);                  /* Au */
        fe_add.fe_add(inner, u2, Au);             /* u^2 + Au */
        fe_add.fe_add(inner, inner, one);         /* u^2 + Au + 1 */
        fe_mul.fe_mul(v2, u, inner);              /* u(u^2 + Au + 1) */
    }
}
