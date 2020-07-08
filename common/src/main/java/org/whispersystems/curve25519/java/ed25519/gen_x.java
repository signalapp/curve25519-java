package org.whispersystems.curve25519.java.ed25519;

import org.whispersystems.curve25519.java.Sha512;
import org.whispersystems.curve25519.java.fe_tobytes;
import org.whispersystems.curve25519.java.ge_p3;

import static org.whispersystems.curve25519.java.ed25519.constants.POINTLEN;
import static org.whispersystems.curve25519.java.ed25519.constants.SCALARLEN;
import static org.whispersystems.curve25519.java.fe_frombytes.fe_frombytes;
import static org.whispersystems.curve25519.java.ge_p3_tobytes.ge_p3_tobytes;
import static org.whispersystems.curve25519.java.ge_scalarmult_base.ge_scalarmult_base;

public class gen_x {

    /**
     * convert z25519 pubkey to edwards pubkey
     * @param ed_pubkey_bytes
     * @param x25519_pubkey_bytes
     * @return 0 if success
     */
    static int convert_25519_pubkey(byte[] ed_pubkey_bytes, byte[] x25519_pubkey_bytes) {
        int[] u = new int[10];
        int[] y =  new int[10];

        if (!fe_isreduced.fe_isreduced(x25519_pubkey_bytes))
            return -1;
        fe_frombytes(u, x25519_pubkey_bytes);
        fe_montx_to_edy.fe_montx_to_edy(y, u);
        fe_tobytes.fe_tobytes(ed_pubkey_bytes, y);
        return 0;
    }


    /**
     * calculate ed_keypair from x25519 privkey
     * @param K_bytes
     * @param k_scalar
     * @param x25519_privkey_scalar
     * @return -1 if not successful
     *          0 is successful
     */
    static int calculate_25519_keypair(byte[] K_bytes, byte[] k_scalar, byte[] x25519_privkey_scalar)
    {
        byte[] kneg = new byte[SCALARLEN];
        ge_p3 ed_pubkey_point = new ge_p3();
        int sign_bit = 0;

        if (SCALARLEN != 32)
            return -1;

        ge_scalarmult_base(ed_pubkey_point, x25519_privkey_scalar);
        ge_p3_tobytes(K_bytes, ed_pubkey_point);

        sign_bit = (K_bytes[31] & 0x80) >> 7;
        System.arraycopy(x25519_privkey_scalar, 0, k_scalar, 0, 32);
        sc_neg.sc_neg(kneg, k_scalar);
        sc_cmov.sc_cmov(k_scalar, kneg, sign_bit);
        K_bytes[31] &= 0x7F;

        kneg = new byte[SCALARLEN];

        return 0;
    }

    /**
     *
     * @param signature_out
     * @param x25519_privkey_scalar
     * @param msg
     * @param msg_len
     * @param random
     * @param sha512provider
     * @param customization_label
     * @param customization_label_len
     * @return -1 if not successful
     *          0 if successful
     */
    public static int generalized_xeddsa_25519_sign(byte[] signature_out,
                              byte[] x25519_privkey_scalar,
                              byte[] msg, long msg_len,
                              byte[] random, Sha512 sha512provider,
                              byte[] customization_label, long customization_label_len)
    {
        byte[] K_bytes = new byte[POINTLEN];
        byte[] k_scalar = new byte[SCALARLEN];
        int retval = -1;

        if (calculate_25519_keypair(K_bytes, k_scalar, x25519_privkey_scalar) != 0)
            return -1;

        retval = gen_eddsa.generalized_eddsa_25519_sign(signature_out,
                K_bytes, k_scalar,
                msg, msg_len, random, sha512provider,
                customization_label, customization_label_len);
        k_scalar = new byte[SCALARLEN];

        return retval;
    }


    /**
     *
     * @param signature_out
     * @param x25519_privkey_scalar
     * @param msg
     * @param msg_len
     * @param random
     * @param sha512provider
     * @param customization_label
     * @param customization_label_len
     * @return -1 if not successful
     *          0 if successful
     */
    public static int generalized_xveddsa_25519_sign(byte[] signature_out,
                                       byte[] x25519_privkey_scalar,
                                       byte[] msg, long msg_len,
                                       byte[] random, Sha512 sha512provider,
                                       byte[] customization_label, long customization_label_len)
    {
        byte[] K_bytes = new byte[POINTLEN];
        byte[] k_scalar = new byte[SCALARLEN];
        int retval = -1;

        if (calculate_25519_keypair(K_bytes, k_scalar, x25519_privkey_scalar) != 0)
            return -1;

        retval = gen_veddsa.generalized_veddsa_25519_sign(signature_out, K_bytes, k_scalar,
                msg, msg_len, random, sha512provider,
                customization_label, customization_label_len);

        k_scalar = new byte[SCALARLEN];

        return retval;
    }

    /**
     *
     * @param vrf_out
     * @param signature
     * @param x25519_pubkey_bytes
     * @param msg
     * @param msg_len
     * @param customization_label
     * @param customization_label_len
     * @param sha512provider
     * @return -1 if not successful
     *          0 if successful
     */
    static int generalized_xveddsa_25519_verify(
                  byte[] vrf_out,
                  byte[] signature,
                  byte[] x25519_pubkey_bytes,
                  byte[] msg, long msg_len,
                  byte[] customization_label, long customization_label_len,
                  Sha512 sha512provider)
    {
        byte[] K_bytes = new byte[POINTLEN];

        if (convert_25519_pubkey(K_bytes, x25519_pubkey_bytes) != 0)
            return -1;

        return gen_veddsa.generalized_veddsa_25519_verify(vrf_out, signature, K_bytes, msg, msg_len,
                customization_label, customization_label_len, sha512provider);
    }
}
