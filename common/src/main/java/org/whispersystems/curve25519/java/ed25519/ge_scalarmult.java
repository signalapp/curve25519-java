package org.whispersystems.curve25519.java.ed25519;

import org.whispersystems.curve25519.java.*;

import static org.whispersystems.curve25519.java.fe_0.fe_0;
import static org.whispersystems.curve25519.java.fe_1.fe_1;
import static org.whispersystems.curve25519.java.fe_cmov.fe_cmov;
import static org.whispersystems.curve25519.java.fe_copy.fe_copy;
import static org.whispersystems.curve25519.java.fe_neg.fe_neg;
import static org.whispersystems.curve25519.java.ge_add.ge_add;
import static org.whispersystems.curve25519.java.ge_p1p1_to_p2.ge_p1p1_to_p2;
import static org.whispersystems.curve25519.java.ge_p1p1_to_p3.ge_p1p1_to_p3;
import static org.whispersystems.curve25519.java.ge_p2_dbl.ge_p2_dbl;
import static org.whispersystems.curve25519.java.ge_p3_0.ge_p3_0;
import static org.whispersystems.curve25519.java.ge_p3_dbl.ge_p3_dbl;
import static org.whispersystems.curve25519.java.ge_p3_to_cached.ge_p3_to_cached;

public class ge_scalarmult {

    /**
     * check if 2 bits are equal
     * @param b
     * @param c
     * @return 1 if yes
     *         0 is no
     */
    static int equal(int b, int c)
    {
        int ub = b;
        int uc = c;
        int x = ub ^ uc;
        int y = x;
        y -= 1;
        y >>= 31;
        return y;
    }

    /**
     *
     * @param b
     * @return -b
     */
    static int negative(int b)
    {
        int x = b;
        x >>= 63;
        return x;
    }

    /**
     *
     * @param t
     * @param u
     * @param b
     */
    static void cmov(ge_cached t, ge_cached u, int b)
    {
        fe_cmov(t.YplusX,u.YplusX,b);
        fe_cmov(t.YminusX,u.YminusX,b);
        fe_cmov(t.Z,u.Z,b);
        fe_cmov(t.T2d,u.T2d,b);
    }

    static void cmov_p3(ge_p3 t, ge_p3 u, int b){
        fe_cmov(t.X, u.X, b);
        fe_cmov(t.Y, u.Y, b);
        fe_cmov(t.Z, u.Z, b);
        fe_cmov(t.T, u.T, b);
    }

    /**
     *
     * @param t
     * @param pre
     * @param b
     */

    static void select(ge_cached t, ge_cached[] pre, int b)
    {
        ge_cached minust = new ge_cached();
        int bnegative = negative(b);
        int babs = b - (((-bnegative) & b) << 1);

        fe_1(t.YplusX);
        fe_1(t.YminusX);
        fe_1(t.Z);
        fe_0(t.T2d);

        cmov(t,pre[0],equal(babs,1));
        cmov(t,pre[1],equal(babs,2));
        cmov(t,pre[2],equal(babs,3));
        cmov(t,pre[3],equal(babs,4));
        cmov(t,pre[4],equal(babs,5));
        cmov(t,pre[5],equal(babs,6));
        cmov(t,pre[6],equal(babs,7));
        cmov(t,pre[7],equal(babs,8));
        fe_copy(minust.YplusX,t.YminusX);
        fe_copy(minust.YminusX,t.YplusX);
        fe_copy(minust.Z,t.Z);
        fe_neg(minust.T2d,t.T2d);
        cmov(t,minust,bnegative);
    }

    /**
     *
     * @param h
     * @param a
     * @param A
     */

    public static void ge_scalarmult_c(ge_p3 h, byte[] a, ge_p3 A)
    {
        byte[] e = new byte[64];
        int carry;
        ge_p1p1 r =  new ge_p1p1();
        ge_p2 s = new ge_p2();
        ge_p3 t0 = new ge_p3(), t1 = new ge_p3(), t2 = new ge_p3();
        ge_cached t = new ge_cached();
        ge_cached[] pre = new ge_cached[8];
        int i;
        
        for (i = 0; i < 8; i++){
            pre[i] = new ge_cached();
        }
        
        for (i = 0;i < 32;++i) {
            e[2 * i + 0] = (byte) ((a[i] >> 0) & 15);
            e[2 * i + 1] = (byte) ((a[i] >> 4) & 15);
        }

        carry = 0;
        for (i = 0;i < 63;++i) {
            e[i] += carry;
            carry = e[i] + 8;
            carry >>= 4;
            e[i] -= carry << 4;
        }
        e[63] += carry;

        ge_p3_to_cached(pre[0], A); //A

        ge_p3_dbl(r, A);
        ge_p1p1_to_p3(t0, r);
        ge_p3_to_cached(pre[1], t0); // 2A

        ge_add(r, A, pre[1]);
        ge_p1p1_to_p3(t1, r);
        ge_p3_to_cached(pre[2], t1); // 3A

        ge_p3_dbl(r, t0);
        ge_p1p1_to_p3(t0, r);
        ge_p3_to_cached(pre[3], t0); // 4A

        ge_add(r, A, pre[3]);
        ge_p1p1_to_p3(t2, r);
        ge_p3_to_cached(pre[4], t2); // 5A

        ge_p3_dbl(r, t1);
        ge_p1p1_to_p3(t1, r);
        ge_p3_to_cached(pre[5], t1); // 6A

        ge_add(r, A, pre[5]);
        ge_p1p1_to_p3(t1, r);
        ge_p3_to_cached(pre[6], t1); // 7A

        ge_p3_dbl(r, t0);
        ge_p1p1_to_p3(t0, r);
        ge_p3_to_cached(pre[7], t0); // 8A

        ge_p3_0(h);

        for (i = 63;i > 0; i--) {
            select(t,pre,e[i]);
            ge_add(r, h, t);
            ge_p1p1_to_p2(s,r);

            ge_p2_dbl(r,s); ge_p1p1_to_p2(s,r);
            ge_p2_dbl(r,s); ge_p1p1_to_p2(s,r);
            ge_p2_dbl(r,s); ge_p1p1_to_p2(s,r);
            ge_p2_dbl(r,s); ge_p1p1_to_p3(h,r);
        }

        select(t,pre,e[0]);
        ge_add(r, h, t);
        ge_p1p1_to_p3(h,r);
    }

    public static void ge_scalarmult(ge_p3 h, byte[] a, ge_p3 A){
        ge_p3 p = new ge_p3(), q = new ge_p3(), t = new ge_p3();
        ge_cached c = new ge_cached();
        ge_p1p1 t0 = new ge_p1p1();

        ge_p3_0.ge_p3_0(q);

        fe_copy(p.T, A.T);
        fe_copy(p.X, A.X);
        fe_copy(p.Y, A.Y);
        fe_copy(p.Z, A.Z);

        int bit = 0;

        for (int i=0; i<256; i++){
            bit = ((a[i>>3]>>(i&7)) & 1);

            // ge add
            ge_p3_to_cached(c, q);
            ge_add(t0, p, c);
            ge_p1p1_to_p3(t, t0);

            cmov_p3(q, t, bit);

            // ge_p3 double
            ge_p2 p2 = new ge_p2();
            ge_p3_to_p2.ge_p3_to_p2(p2, p);
            ge_p1p1 p1 = new ge_p1p1();
            ge_p3_dbl(p1, p);
            ge_p1p1_to_p3(p, p1);
        }
        fe_copy(h.X, q.X);
        fe_copy(h.Y, q.Y);
        fe_copy(h.Z, q.Z);
        fe_copy(h.T, q.T);
    }
}
