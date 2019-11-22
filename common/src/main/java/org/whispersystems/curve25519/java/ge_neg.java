package org.whispersystems.curve25519.java;

public class ge_neg {
    public static void ge_neg(ge_p3 r, ge_p3 p)
    {
        fe_neg.fe_neg(r.X, p.X);
        fe_copy.fe_copy(r.Y, p.Y);
        fe_copy.fe_copy(r.Z, p.Z);
        fe_neg.fe_neg(r.T, p.T);
    }
}
