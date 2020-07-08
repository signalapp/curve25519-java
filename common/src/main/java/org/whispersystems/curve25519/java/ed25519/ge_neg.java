package org.whispersystems.curve25519.java.ed25519;

import org.whispersystems.curve25519.java.ge_p3;

import static org.whispersystems.curve25519.java.fe_copy.fe_copy;
import static org.whispersystems.curve25519.java.fe_neg.fe_neg;

public class ge_neg {

    /**
     * return r = -p
     * @param r
     * @param p
     */
    public static void ge_neg(ge_p3 r, ge_p3 p)
    {
        fe_neg(r.X, p.X);
        fe_copy(r.Y, p.Y);
        fe_copy(r.Z, p.Z);
        fe_neg(r.T, p.T);
    }
}
