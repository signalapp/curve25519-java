package org.whispersystems.curve25519.java.ed25519;

import org.whispersystems.curve25519.java.ge_p1p1;
import org.whispersystems.curve25519.java.ge_p2;
import org.whispersystems.curve25519.java.ge_p3;

import static org.whispersystems.curve25519.java.ge_p1p1_to_p2.ge_p1p1_to_p2;
import static org.whispersystems.curve25519.java.ge_p1p1_to_p3.ge_p1p1_to_p3;
import static org.whispersystems.curve25519.java.ge_p2_dbl.ge_p2_dbl;
import static org.whispersystems.curve25519.java.ge_p3_dbl.ge_p3_dbl;

public class ge_scalarmult_cofactor {

    /**
     * q = 8*p
     * @param q
     * @param p
     */
    static void ge_scalarmult_cofactor(ge_p3 q, ge_p3 p)
    {
        ge_p1p1 p1p1 = new ge_p1p1();
        ge_p2 p2 = new ge_p2();

        ge_p3_dbl(p1p1, p);
        ge_p1p1_to_p2(p2, p1p1);

        ge_p2_dbl(p1p1, p2);
        ge_p1p1_to_p2(p2, p1p1);

        ge_p2_dbl(p1p1, p2);
        ge_p1p1_to_p3(q, p1p1);
    }
}
