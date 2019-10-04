package org.whispersystems.curve25519.java;

public class veddsa {
    final static int BLOCKLEN = 128; /* SHA512 */
    final static int HASHLEN = 64;  /* SHA512 */
    final static int POINTLEN = 32;
    final static int SCALARLEN = 32;
    final static int RANDLEN = 32;
    final static int MSTART = 2048;
    final static int MSGMAXLEN = 1048576;
    final static int BUFLEN = 1024;
    final static int VRFOUTPUTLEN = 32;

    /* B: base point 
     * R: commitment (point), 
       r: private nonce (scalar)
       K: encoded public key
       k: private key (scalar)
       Z: 32-bytes random
       M: buffer containing message, message starts at M_start, continues for M_len
       r = hash(B || gen_labelset || Z || pad1 || k || pad2 || gen_labelset || K || extra || M) (mod q)
    */
    public static boolean generalized_commit(Sha512 sha512provider, byte[] R_bytes, byte[] r_scalar,
                                         byte[] labelset,
                                         byte[] extra, int extra_len,
                                         byte[] K_bytes, byte[] k_scalar,
                                         byte[] Z, byte[] msg,
                                         byte[] M_buf, int M_start, int M_len) {
        ge_p3 R_point = new ge_p3();
        byte[] hash = new byte[64];

        if (!gen_labelset.labelset_validate(labelset)) {
            return false;
        }
        if (R_bytes == null || r_scalar == null ||
                K_bytes == null || k_scalar == null ||
                Z == null) {
            return false;
        }
        if (extra == null || extra.length == 0) {
            return false;
        }
        if (gen_labelset.labelset_is_empty(labelset)) {
            return false;
        }

        int prefix_len = 0;
        prefix_len += POINTLEN + labelset.length + RANDLEN;
        int pad_len1 = ((BLOCKLEN - (prefix_len % BLOCKLEN)) % BLOCKLEN);
        prefix_len += pad_len1;
        prefix_len += SCALARLEN;
        int pad_len2 = ((BLOCKLEN - (prefix_len % BLOCKLEN)) % BLOCKLEN);
        prefix_len += pad_len2;
        prefix_len += labelset.length + POINTLEN + extra_len;
        if (prefix_len > M_start) {
            return false;
        }

        int startIndex = M_start - prefix_len;

        System.arraycopy(gen_labelset.B_bytes, 0, M_buf, startIndex, POINTLEN);
        System.arraycopy(labelset, 0, M_buf, startIndex + POINTLEN, labelset.length);
        System.arraycopy(Z, 0, M_buf, startIndex + POINTLEN + labelset.length, RANDLEN);
        System.arraycopy(k_scalar, 0, M_buf, startIndex + POINTLEN + labelset.length + pad_len1 + RANDLEN, POINTLEN);
        System.arraycopy(labelset, 0, M_buf, startIndex + 2 * POINTLEN + labelset.length + pad_len1 + RANDLEN + pad_len2, labelset.length);
        System.arraycopy(K_bytes, 0, M_buf, startIndex + 2 * POINTLEN + 2 * labelset.length + pad_len1 + RANDLEN + pad_len2, POINTLEN);
        System.arraycopy(extra, 0, M_buf, startIndex + 3 * POINTLEN + 2 * labelset.length + pad_len1 + RANDLEN + pad_len2, extra_len);

        byte[] in = java.util.Arrays.copyOfRange(M_buf, startIndex, M_start + M_len);
        sha512provider.calculateDigest(hash, in, in.length);

        sc_reduce.sc_reduce(hash);
        ge_scalarmult_base.ge_scalarmult_base(R_point, hash);
        ge_p3_tobytes.ge_p3_tobytes(R_bytes, R_point);
        System.arraycopy(hash, 0, r_scalar, 0, SCALARLEN);
        return true;
    }



    /* if is_labelset_empty(gen_labelset):
           return hash(R || K || M) (mod q)
       else:
           return hash(B || gen_labelset || R || gen_labelset || K || extra || M) (mod q)
    */
    public static int generalized_challenge(Sha512 sha512provider, byte[] h_scalar,
                                            byte[] labelset,
                                            byte[] extra,
                                            byte[] R_bytes,
                                            byte[] K_bytes,
                                            byte[] M_buf, int M_start, int M_len) {

        byte[] hash = new byte[HASHLEN];

        if (h_scalar == null) return -1;

        if (!gen_labelset.labelset_validate(labelset)) return -1;
        if (R_bytes == null || K_bytes == null) return -1;
        if (extra != null && gen_labelset.labelset_is_empty(labelset)) return -1;

        int prefix_len;

        if (gen_labelset.labelset_is_empty(labelset)) {
            if (2 * POINTLEN > MSTART) return -1;
            prefix_len = 2 * POINTLEN;
            int startIndex = M_start - prefix_len;
            System.arraycopy(R_bytes, 0, M_buf, startIndex, POINTLEN);
            System.arraycopy(K_bytes, 0, M_buf, startIndex + POINTLEN, POINTLEN);
        } else {
            prefix_len = 3 * POINTLEN + 2 * labelset.length + extra.length;
            int startIndex = M_start - prefix_len;
            System.arraycopy(gen_labelset.B_bytes, 0, M_buf, startIndex, POINTLEN);
            System.arraycopy(labelset, 0, M_buf, startIndex + POINTLEN, labelset.length);
            System.arraycopy(R_bytes, 0, M_buf, startIndex + POINTLEN + labelset.length, POINTLEN);
            System.arraycopy(labelset, 0, M_buf, startIndex + 2 * POINTLEN + labelset.length, labelset.length);
            System.arraycopy(K_bytes, 0, M_buf, startIndex + 2 * POINTLEN + 2 * labelset.length, POINTLEN);
            System.arraycopy(extra, 0, M_buf, startIndex + 3 * POINTLEN + 2 * labelset.length, extra.length);
        }

        byte[] in = java.util.Arrays.copyOfRange(M_buf, M_start - prefix_len, M_start + M_len);
        sha512provider.calculateDigest(hash, in, in.length);
        sc_reduce.sc_reduce(hash);
        System.arraycopy(hash, 0, h_scalar, 0, SCALARLEN);
        return 0;
    }

    /* return r + kh (mod q) */
    public static int generalized_prove(byte[] out_scalar, byte[] r_scalar, byte[] k_scalar, byte[] h_scalar) {
        sc_muladd.sc_muladd(out_scalar, h_scalar, k_scalar, r_scalar);
        return 0;
    }

    /* R = s*B - h*K */
    public static int generalized_solve_commitment(byte[] R_bytes_out, ge_p3 K_point_out,
                                                   ge_p3 B_point, byte[] s_scalar,
                                                   byte[] K_bytes, byte[] h_scalar) {
        ge_p3 Kneg_point = new ge_p3();
        ge_p2 R_calc_point_p2 = new ge_p2();

        ge_p3 sB = new ge_p3();
        ge_p3 hK = new ge_p3();
        ge_p3 R_calc_point_p3 = new ge_p3();

        if (ge_frombytes.ge_frombytes_negate_vartime(Kneg_point, K_bytes) != 0) {
            return -1;
        }

        if (B_point == null) {
            ge_double_scalarmult.ge_double_scalarmult_vartime(R_calc_point_p2, h_scalar, Kneg_point, s_scalar);
            ge_tobytes.ge_tobytes(R_bytes_out, R_calc_point_p2);
        } else {
            // s * Bv
            ge_scalarmult.ge_scalarmult(sB, s_scalar, B_point);

            // h * -K
            ge_scalarmult.ge_scalarmult(hK, h_scalar, Kneg_point);

            // R = sB - hK
            ge_p3_add.ge_p3_add(R_calc_point_p3, sB, hK);
            ge_p3_tobytes.ge_p3_tobytes(R_bytes_out, R_calc_point_p3);
        }

        if (K_point_out != null) {
            ge_neg.ge_neg(K_point_out, Kneg_point);
        }

        return 0;
    }

    public static boolean generalized_calculate_Bv(Sha512 sha512provider, ge_p3 Bv_point,
                                               byte[] labelset, byte[] K_bytes,
                                               byte[] M_buf, int M_start, int M_len) {
        if (!gen_labelset.labelset_validate(labelset))
            return false;
        if (Bv_point == null || K_bytes == null || M_buf == null)
            return false;

        int prefix_len = 2 * POINTLEN + labelset.length;
        if (prefix_len > M_start)
            return false;

        int startIndex = M_start - prefix_len;
        System.arraycopy(gen_labelset.B_bytes, 0, M_buf, startIndex, POINTLEN);
        System.arraycopy(labelset, 0, M_buf, startIndex + POINTLEN, labelset.length);
        System.arraycopy(K_bytes, 0, M_buf, startIndex + POINTLEN + labelset.length, POINTLEN);

        byte[] in = java.util.Arrays.copyOfRange(M_buf, startIndex, M_start + M_len);
        System.arraycopy(M_buf, M_start, in, in.length - M_len, M_len);
        elligator.hash_to_point(sha512provider, Bv_point, in);
        return !ge_isneutral.ge_isneutral(Bv_point);
    }

    public static int generalized_calculate_vrf_output(Sha512 sha512provider,
                                                       byte[] vrf_output,
                                                       byte[] labelset,
                                                       ge_p3 cKv_point) {
        byte[] cKv_bytes = new byte[POINTLEN];
        byte[] hash = new byte[HASHLEN];

        if (vrf_output == null) return -1;
        Arrays.fill(vrf_output, (byte) 0);

        if (labelset.length + 2 * POINTLEN > BUFLEN)
            return -1;
        if (!gen_labelset.labelset_validate(labelset))
            return -1;
        if (cKv_point == null)
            return -1;

        ge_p3_tobytes.ge_p3_tobytes(cKv_bytes, cKv_point);

        byte[] buf = new byte[2 * POINTLEN + labelset.length];
        System.arraycopy(gen_labelset.B_bytes, 0, buf, 0, POINTLEN);
        System.arraycopy(labelset, 0, buf, POINTLEN, labelset.length);
        System.arraycopy(cKv_bytes, 0, buf, POINTLEN + labelset.length, POINTLEN);

        sha512provider.calculateDigest(hash, buf, buf.length);
        System.arraycopy(hash, 0, vrf_output, 0, VRFOUTPUTLEN);
        return 0;
    }

    public static boolean generalized_veddsa_25519_sign(
            Sha512 sha512provider,
            byte[] signature_out,
            byte[] eddsa_25519_pubkey_bytes,
            byte[] eddsa_25519_privkey_scalar,
            byte[] msg,
            byte[] random,
            byte[] customization_label) {
        if (signature_out == null) {
            return false;
        }

        if (eddsa_25519_pubkey_bytes == null) {
            return false;
        }
        if (eddsa_25519_privkey_scalar == null) {
            return false;
        }
        if (customization_label == null || customization_label.length > gen_labelset.LABELMAXLEN) {
            return false;
        }
        if (msg == null || msg.length > MSGMAXLEN) {
            return false;
        }

        ge_p3 Bv_point = new ge_p3();
        ge_p3 Kv_point = new ge_p3();
        ge_p3 Rv_point = new ge_p3();

        byte[] Bv_bytes = new byte[POINTLEN];
        byte[] Kv_bytes = new byte[POINTLEN];
        byte[] Rv_bytes = new byte[POINTLEN];
        byte[] R_bytes = new byte[POINTLEN];
        byte[] r_scalar = new byte[SCALARLEN];
        byte[] h_scalar = new byte[SCALARLEN];
        byte[] s_scalar = new byte[SCALARLEN];
        byte[] extra = new byte[3 * POINTLEN];
        byte[] M_buf = new byte[msg.length + MSTART];
        String protocol_name = "VEdDSA_25519_SHA512_Elligator2";

        System.arraycopy(msg, 0, M_buf, MSTART, msg.length);

        byte[] labelset = gen_labelset.labelset_new(protocol_name, customization_label);

        //  labelset1 = add_label(labels, "1")
        //  Bv = hash(hash(labelset1 || K) || M)
        //  Kv = k * Bv
        labelset = gen_labelset.labelset_add(labelset, "1");
        generalized_calculate_Bv(sha512provider, Bv_point, labelset,
                eddsa_25519_pubkey_bytes, M_buf, MSTART, msg.length);
        ge_scalarmult.ge_scalarmult(Kv_point, eddsa_25519_privkey_scalar, Bv_point);
        ge_p3_tobytes.ge_p3_tobytes(Bv_bytes, Bv_point);
        ge_p3_tobytes.ge_p3_tobytes(Kv_bytes, Kv_point);

        //  labelset2 = add_label(labels, "2")
        //  R, r = commit(labelset2, (Bv || Kv), (K,k), Z, M)
        labelset[labelset.length - 1] = '2';
        System.arraycopy(Bv_bytes, 0, extra, 0, POINTLEN);
        System.arraycopy(Kv_bytes, 0, extra, POINTLEN, POINTLEN);
        if (!generalized_commit(sha512provider, R_bytes, r_scalar,
                labelset,
                extra, 2 * POINTLEN,
                eddsa_25519_pubkey_bytes, eddsa_25519_privkey_scalar,
                random, msg, M_buf, MSTART, msg.length)) {
            return false;
        }

        //  Rv = r * Bv
        ge_scalarmult.ge_scalarmult(Rv_point, r_scalar, Bv_point);
        ge_p3_tobytes.ge_p3_tobytes(Rv_bytes, Rv_point);

        //  labelset3 = add_label(labels, "3")
        //  h = challenge(labelset3, (Bv || Kv || Rv), R, K, M)
        labelset[labelset.length - 1] = '3';
//        memcpy(extra + 2*POINTLEN, Rv_bytes, POINTLEN);
        System.arraycopy(Rv_bytes, 0, extra, 2 * POINTLEN, POINTLEN);
        if (generalized_challenge(sha512provider, h_scalar,
                labelset, extra, R_bytes, eddsa_25519_pubkey_bytes, M_buf, MSTART, msg.length) != 0) {
            return false;
        }

        //  s = prove(r, k, h)
        if (generalized_prove(s_scalar, r_scalar, eddsa_25519_privkey_scalar, h_scalar) != 0) {
            return false;
        }

        //  return (Kv || h || s)
        System.arraycopy(Kv_bytes, 0, signature_out, 0, POINTLEN);
        System.arraycopy(h_scalar, 0, signature_out, POINTLEN, SCALARLEN);
        System.arraycopy(s_scalar, 0, signature_out, POINTLEN + SCALARLEN, SCALARLEN);

        Arrays.fill(r_scalar, (byte) 0);

        return true;
    }

    public static int generalized_veddsa_25519_verify(
            Sha512 sha512provider,
            byte[] vrf_output,
            byte[] signature,
            byte[] eddsa_25519_pubkey_bytes,
            byte[] msg,
            byte[] customization_label) {
        if (signature == null) return -1;
        if (eddsa_25519_pubkey_bytes == null) return -1;
        if (msg == null) return -1;
        if (customization_label == null) return -1;
        if (customization_label.length > gen_labelset.LABELMAXLEN) return -1;
        if (msg.length > MSGMAXLEN) return -1;

        ge_p3 Bv_point = new ge_p3();
        ge_p3 K_point = new ge_p3();
        ge_p3 Kv_point = new ge_p3();
        ge_p3 cK_point = new ge_p3();
        ge_p3 cKv_point = new ge_p3();

        byte[] Bv_bytes = new byte[POINTLEN];
        byte[] R_calc_bytes = new byte[POINTLEN];
        byte[] Rv_calc_bytes = new byte[POINTLEN];
        byte[] h_calc_scalar = new byte[SCALARLEN];
        byte[] extra = new byte[3 * POINTLEN];
        String protocol_name = "VEdDSA_25519_SHA512_Elligator2";

        byte[] M_buf = new byte[msg.length + MSTART];
        System.arraycopy(msg, 0, M_buf, MSTART, msg.length);

        byte[] Kv_bytes = new byte[POINTLEN];
        System.arraycopy(signature, 0, Kv_bytes, 0, POINTLEN);
        byte[] h_scalar = new byte[SCALARLEN];
        System.arraycopy(signature, POINTLEN, h_scalar, 0, SCALARLEN);
        byte[] s_scalar = new byte[SCALARLEN];
        System.arraycopy(signature, POINTLEN + SCALARLEN, s_scalar, 0, SCALARLEN);

        if (!point_isreduced.point_isreduced(eddsa_25519_pubkey_bytes)) return -1;
        if (!point_isreduced.point_isreduced(Kv_bytes)) return -1;
        if (!sc_isreduced.sc_isreduced(h_scalar)) return -1;
        if (!sc_isreduced.sc_isreduced(s_scalar)) return -1;

        //  gen_labelset = new_labelset(protocol_name, customization_label)
        byte[] labelset = gen_labelset.labelset_new(protocol_name, customization_label);

        //  labelset1 = add_label(labels, "1")
        //  Bv = hash(hash(labelset1 || K) || M)
        labelset = gen_labelset.labelset_add(labelset, "1");
        if (!generalized_calculate_Bv(sha512provider, Bv_point, labelset, eddsa_25519_pubkey_bytes, M_buf, MSTART, msg.length)) return -1;
        ge_p3_tobytes.ge_p3_tobytes(Bv_bytes, Bv_point);

        //  R = solve_commitment(B, s, K, h)
        if (generalized_solve_commitment(R_calc_bytes, K_point, null,
                s_scalar, eddsa_25519_pubkey_bytes, h_scalar) != 0) return -1;

        //  Rv = solve_commitment(Bv, s, Kv, h)
        if (generalized_solve_commitment(Rv_calc_bytes, Kv_point, Bv_point,
                s_scalar, Kv_bytes, h_scalar) != 0) return -1;

        ge_scalarmult_cofactor.ge_scalarmult_cofactor(cK_point, K_point);
        ge_scalarmult_cofactor.ge_scalarmult_cofactor(cKv_point, Kv_point);
        if (ge_isneutral.ge_isneutral(cK_point) || ge_isneutral.ge_isneutral(cKv_point) || ge_isneutral.ge_isneutral(Bv_point)) return -1;

        //  labelset3 = add_label(labels, "3")
        //  h = challenge(labelset3, (Bv || Kv || Rv), R, K, M)
        labelset[labelset.length - 1] = '3';
        System.arraycopy(Bv_bytes, 0, extra, 0, POINTLEN);
        System.arraycopy(Kv_bytes, 0, extra, POINTLEN, POINTLEN);
        System.arraycopy(Rv_calc_bytes, 0, extra, 2 * POINTLEN, POINTLEN);
        if (generalized_challenge(sha512provider, h_calc_scalar,
                labelset,
                extra,
                R_calc_bytes, eddsa_25519_pubkey_bytes, M_buf, MSTART, msg.length) != 0) return -1;

        // if bytes_equal(h, h')
        if (crypto_verify_32.crypto_verify_32(h_scalar, h_calc_scalar) != 0) return -1;

        //  labelset4 = add_label(labels, "4")
        //  v = hash(labelset4 || c*Kv)
        labelset[labelset.length - 1] = '4';

        return generalized_calculate_vrf_output(sha512provider, vrf_output, labelset, cKv_point);
    }
}
