package org.whispersystems.curve25519.java.ed25519;

import org.whispersystems.curve25519.java.ge_cached;
import org.whispersystems.curve25519.java.ge_p1p1;
import org.whispersystems.curve25519.java.ge_p3;

import static org.whispersystems.curve25519.java.ge_add.ge_add;
import static org.whispersystems.curve25519.java.ge_p1p1_to_p3.ge_p1p1_to_p3;
import static org.whispersystems.curve25519.java.ge_p3_to_cached.ge_p3_to_cached;

public class ge_p3_add {

    /**
     * r = p+q
     * @param r
     * @param p
     * @param q
     */
    static void ge_p3_add(ge_p3 r, ge_p3 p, ge_p3 q)
    {
        ge_cached p_cached = new ge_cached();
        ge_p1p1 r_p1p1 = new ge_p1p1();

        ge_p3_to_cached(p_cached, p);
        ge_add(r_p1p1, q, p_cached);
        ge_p1p1_to_p3(r, r_p1p1);
    }
}
