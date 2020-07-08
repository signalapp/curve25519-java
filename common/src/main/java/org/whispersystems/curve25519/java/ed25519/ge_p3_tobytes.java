package org.whispersystems.curve25519.java.ed25519;

import org.whispersystems.curve25519.java.*;

public class ge_p3_tobytes {

    public static int ge_p3_tobytes(byte[] s, ge_p3 p){
        int [] recip = new int[10], x = new int[10], y = new int[10], fe = new int[10];

        fe_invert.fe_invert(recip, p.Z);
        fe_mul.fe_mul(x, p.X, recip);
        fe_mul.fe_mul(y, p.Y, recip);
        fe_tobytes.fe_tobytes(s, y);

        s[31] ^= fe_isnegative.fe_isnegative(x) << 7;

        return 0;
    }

}
