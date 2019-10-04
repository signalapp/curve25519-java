package org.whispersystems.curve25519.java;

public class gen_x {
    public static final int SCALARLEN = 32;
    public static final int POINTLEN = 32;

    /*
     * Convert the X25519 public key into an Ed25519 public key.
     * y = (u - 1) / (u + 1)
     * NOTE: u=-1 is converted to y=0 since fe_invert is mod-exp
    */
    public static int convert_25519_pubkey(byte[] ed_pubkey_bytes, byte[] x25519_pubkey_bytes) {
        int[] u = new int[10];
        int[] y = new int[10];

        if (!fe_isreduced.fe_isreduced(x25519_pubkey_bytes))
            return -1;

        fe_frombytes.fe_frombytes(u, x25519_pubkey_bytes);

        fe_montx_to_edy.fe_montx_to_edy(y, u);

        fe_tobytes.fe_tobytes(ed_pubkey_bytes, y);
        return 0;
    }

    public static int calculate_25519_keypair(byte[] K_bytes, byte[] k_scalar,
                                              byte[] x25519_privkey_scalar) {
        byte[] kneg = new byte[SCALARLEN];
        ge_p3 ed_pubkey_point = new ge_p3(); /* Ed25519 pubkey point */

        /* Convert the Curve25519 privkey to an Ed25519 public key */
        ge_scalarmult_base.ge_scalarmult_base(ed_pubkey_point, x25519_privkey_scalar);
        ge_p3_tobytes.ge_p3_tobytes(K_bytes, ed_pubkey_point);

        /* Force Edwards sign bit to zero */
        byte sign_bit = (byte) ((K_bytes[31] & 0x80) >> 7);
        System.arraycopy(x25519_privkey_scalar, 0, k_scalar, 0, 32);
        sc_neg.sc_neg(kneg, k_scalar);
        sc_cmov.sc_cmov(k_scalar, kneg, sign_bit);
        K_bytes[31] &= 0x7F;

        Arrays.fill(kneg, (byte) 0);
        return 0;
    }

    public static boolean generalized_xveddsa_25519_sign(
            Sha512 sha512provider,
            byte[] signature_out,
            byte[] x25519_privkey_scalar,
            byte[] msg,
            byte[] random) {
        byte[] K_bytes = new byte[POINTLEN];
        byte[] k_scalar = new byte[SCALARLEN];
        if (calculate_25519_keypair(K_bytes, k_scalar, x25519_privkey_scalar) != 0)
            return false;

        boolean retval = veddsa.generalized_veddsa_25519_sign(sha512provider, signature_out, K_bytes, k_scalar,
                msg, random, new byte[]{});
        Arrays.fill(k_scalar, (byte) 0);
        return retval;
    }

    public static int generalized_xveddsa_25519_verify(
            Sha512 sha512provider,
            byte[] vrf_output,
            byte[] signature,
            byte[] x25519_pubkey_bytes,
            byte[] msg) {
        byte[] K_bytes = new byte[POINTLEN];

        if (convert_25519_pubkey(K_bytes, x25519_pubkey_bytes) != 0)
            return -1;

        return veddsa.generalized_veddsa_25519_verify(sha512provider, vrf_output, signature, K_bytes, msg,
                new byte[]{});
    }

}
