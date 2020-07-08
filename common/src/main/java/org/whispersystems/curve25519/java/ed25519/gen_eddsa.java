package org.whispersystems.curve25519.java.ed25519;

import org.whispersystems.curve25519.java.Sha512;
import org.whispersystems.curve25519.java.ge_p2;
import org.whispersystems.curve25519.java.ge_p3;

import static org.whispersystems.curve25519.java.ed25519.constants.*;
import static org.whispersystems.curve25519.java.ed25519.gen_labelset.*;
import static org.whispersystems.curve25519.java.ge_double_scalarmult.ge_double_scalarmult_vartime;
import static org.whispersystems.curve25519.java.ge_frombytes.ge_frombytes_negate_vartime;
import static org.whispersystems.curve25519.java.ge_p3_tobytes.ge_p3_tobytes;
import static org.whispersystems.curve25519.java.ge_scalarmult_base.ge_scalarmult_base;
import static org.whispersystems.curve25519.java.ge_tobytes.ge_tobytes;
import static org.whispersystems.curve25519.java.sc_muladd.sc_muladd;
import static org.whispersystems.curve25519.java.sc_reduce.sc_reduce;

public class gen_eddsa {

    /* B: base point 
     * R: commitment (point),
       r: private nonce (scalar)
       K: encoded public key
       k: private key (scalar)
       Z: 32-bytes random
       M: buffer containing message, message starts at M_start, continues for M_len
       r = hash(B || labelset || Z || pad1 || k || pad2 || labelset || K || extra || M) (mod q)
    */

    /**
     * VRF Commitment
     * @param R_bytes
     * @param r_scalar
     * @param labelset
     * @param labelset_len
     * @param extra
     * @param extra_len
     * @param K_bytes
     * @param k_scalar
     * @param Z
     * @param sha512provider
     * @param M_buf
     * @param M_start
     * @param M_len
     * @return  0 if success
     *          1 otherwise
     */
    static int generalized_commit(byte[] R_bytes, byte[] r_scalar,
                           byte[] labelset, long labelset_len,
                           byte[] extra, long extra_len,
                           byte[] K_bytes, byte[] k_scalar, 
                           byte[] Z, Sha512 sha512provider,
                           byte[] M_buf, long M_start, long M_len)
    {
        ge_p3 R_point = new ge_p3();
        byte[] hash = new byte[(int) HASHLEN];
        long bufstart = 0;
        long bufptr = 0;
        long bufend = 0;
        long prefix_len = 0;

        if (labelset_validate(labelset, labelset_len) != 0) {
            zeroize_commit(hash, M_buf, M_start, prefix_len);
            return -1;
        }
        if (R_bytes == null || r_scalar == null ||
            K_bytes == null || k_scalar == null ||
            Z == null || M_buf == null) {
            zeroize_commit(hash, M_buf, M_start, prefix_len);
            return -1;
        }
        if (extra == null && extra_len != 0) {
            zeroize_commit(hash, M_buf, M_start, prefix_len);
            return -1;
        }
        if (extra != null && extra_len == 0) {
            zeroize_commit(hash, M_buf, M_start, prefix_len);
            return -1;
        }
        if (extra != null && labelset_is_empty(labelset, labelset_len)) {
            zeroize_commit(hash, M_buf, M_start, prefix_len);
            return -1;
        }
        if (HASHLEN != 64) {
            zeroize_commit(hash, M_buf, M_start, prefix_len);
            return -1;
        }

        prefix_len = 0;
        prefix_len += POINTLEN + labelset_len + RANDLEN;
        prefix_len += ((BLOCKLEN - (prefix_len % BLOCKLEN)) % BLOCKLEN);
        prefix_len += SCALARLEN;
        prefix_len += ((BLOCKLEN - (prefix_len % BLOCKLEN)) % BLOCKLEN);
        prefix_len += labelset_len + POINTLEN + extra_len;
        if (prefix_len > M_start) {
            zeroize_commit(hash, M_buf, M_start, prefix_len);
            return -1;
        }

        bufstart = M_start - prefix_len;
        bufptr = bufstart;
        bufend = M_start;
        bufptr = buffer_add(B_bytes, 0, POINTLEN, M_buf, bufptr, bufend);
        bufptr = buffer_add(labelset, 0, labelset_len, M_buf, bufptr, bufend);
        bufptr = buffer_add(Z, 0, RANDLEN, M_buf, bufptr, bufend);
        bufptr = buffer_pad(M_buf, bufptr, bufend, bufstart);
        bufptr = buffer_add(k_scalar, 0, SCALARLEN, M_buf, bufptr, bufend);
        bufptr = buffer_pad(M_buf, bufptr, bufend, bufstart);
        bufptr = buffer_add(labelset, 0, labelset_len, M_buf, bufptr, bufend);
        bufptr = buffer_add(K_bytes, 0, POINTLEN, M_buf, bufptr, bufend);
        bufptr = buffer_add(extra, 0, extra_len, M_buf, bufptr, bufend);
        if (bufptr != bufend || bufptr != M_start || bufptr - bufstart != prefix_len || bufptr < 0) {
            zeroize_commit(hash, M_buf, M_start, prefix_len);
            return -1;
        }

        byte[] M_buf_start_prefix = new byte[(int) (prefix_len + M_len)];
        System.arraycopy(M_buf, (int) (M_start - prefix_len), M_buf_start_prefix, 0, (int) (prefix_len + M_len));
        sha512provider.calculateDigest(hash, M_buf_start_prefix, prefix_len + M_len);
        sc_reduce(hash);
        ge_scalarmult_base(R_point, hash);
        ge_p3_tobytes(R_bytes, R_point);
        System.arraycopy(hash, 0, r_scalar, 0, (int) SCALARLEN);

        // ZEROIZE:
        zeroize_commit(hash, M_buf, M_start, prefix_len);
        return 0;
    }

    /**
     * Zeroize all arrays used in generalized_commit
     * @param hash
     * @param M_buf
     * @param M_start
     * @param prefix_len
     */
    private static void zeroize_commit(byte[] hash, byte[] M_buf, long M_start, long prefix_len){
        byte[] zero = new byte[(int) HASHLEN];
        System.arraycopy(zero, 0, hash, 0, (int) HASHLEN);
        zero = new byte[(int) prefix_len];
        System.arraycopy(zero, 0, M_buf, (int) (M_start-prefix_len), (int) (prefix_len));
    }

    /* if is_labelset_empty(labelset):
           return hash(R || K || M) (mod q)
       else:
           return hash(B || labelset || R || labelset || K || extra || M) (mod q)
    */

    /**
     * Challenge commitment
     * @param h_scalar
     * @param labelset
     * @param labelset_len
     * @param extra
     * @param extra_len
     * @param R_bytes
     * @param K_bytes
     * @param M_buf
     * @param M_start
     * @param M_len
     * @param sha512provider
     * @return
     */
    static int generalized_challenge(byte[] h_scalar,
                              byte[] labelset, long labelset_len,
                              byte[] extra, long extra_len,
                              byte[] R_bytes,
                              byte[] K_bytes,
                              byte[] M_buf, long M_start, long M_len,
                              Sha512 sha512provider)
    {
        byte[] hash =  new byte[(int) HASHLEN];
        long bufstart = 0;
        long bufptr = 0;
        long bufend = 0;
        long prefix_len = 0;

        if (h_scalar == null)
            return -1;

        if (h_scalar.length != SCALARLEN)
            return -1;

        if (labelset_validate(labelset, labelset_len) != 0)
            return -1;
        if (R_bytes == null || K_bytes == null || M_buf == null)
            return -1;
        if (extra == null && extra_len != 0)
            return -1;
        if (extra != null && extra_len == 0)
            return -1;
        if (extra != null && labelset_is_empty(labelset, labelset_len))
            return -1;
        if (HASHLEN != 64)
            return -1;

        if (labelset_is_empty(labelset, labelset_len)) {
            if (2*POINTLEN > M_start)
              return -1;
            if (extra != null || extra_len != 0)
              return -1;
            System.arraycopy(R_bytes, 0, M_buf, (int) (M_start - (2*POINTLEN)), (int) POINTLEN);
            System.arraycopy(K_bytes, 0, M_buf, (int) (M_start - (1*POINTLEN)), (int) POINTLEN);
            prefix_len = 2*POINTLEN;
        } else {
            prefix_len = 3*POINTLEN + 2*labelset_len + extra_len;
            if (prefix_len > M_start)
              return -1;

            bufstart = M_start - prefix_len;
            bufptr = bufstart;
            bufend = M_start;
            bufptr = buffer_add(B_bytes, 0, POINTLEN, M_buf, bufptr, bufend);
            bufptr = buffer_add(labelset, 0, labelset_len, M_buf, bufptr, bufend);
            bufptr = buffer_add(R_bytes, 0, POINTLEN, M_buf, bufptr, bufend);
            bufptr = buffer_add(labelset, 0, labelset_len, M_buf, bufptr, bufend);
            bufptr = buffer_add(K_bytes, 0, POINTLEN, M_buf, bufptr, bufend);
            bufptr = buffer_add(extra, 0, extra_len, M_buf, bufptr, bufend);

            if (bufptr < 0)
              return -1;
            if (bufptr != bufend || bufptr != M_start || bufptr - bufstart != prefix_len)
              return -1;
        }

        byte[] M_buf_start_prefix = new byte[(int) (prefix_len + M_len)];
        System.arraycopy(M_buf, (int) (M_start - prefix_len), M_buf_start_prefix, 0, (int) (prefix_len + M_len));
        sha512provider.calculateDigest(hash, M_buf_start_prefix, (int) (prefix_len + M_len));
        sc_reduce(hash);
        System.arraycopy(hash, 0, h_scalar, 0, (int) SCALARLEN);
        return 0;
    }

    /* return r + kh (mod q) */

    /**
     * prove VRF hash output
     * @param out_scalar
     * @param r_scalar
     * @param k_scalar
     * @param h_scalar
     * @return
     */
    static int generalized_prove(byte[]out_scalar, byte[] r_scalar, byte[] k_scalar, byte[] h_scalar)
    {
        sc_muladd(out_scalar, h_scalar, k_scalar, r_scalar);

        // Zeroize Stack:
        byte[] m = new byte[1024];

        return 0;
    }


    static int generalized_solve_commitment(byte[] R_bytes_out,  ge_p3 K_point_out,
                                 ge_p3 B_point, byte[] s_scalar,
                                 byte[] K_bytes, byte[] h_scalar)
    {

        ge_p3 Kneg_point = new ge_p3();
        ge_p2 R_calc_point_p2 = new ge_p2();

        ge_p3 sB = new ge_p3();
        ge_p3 hK = new ge_p3();
        ge_p3 R_calc_point_p3 = new ge_p3();

        if (ge_frombytes_negate_vartime(Kneg_point, K_bytes) != 0){
            return -1;
        }


        if (B_point == null) {
            ge_double_scalarmult_vartime(R_calc_point_p2, h_scalar, Kneg_point, s_scalar);
            ge_tobytes(R_bytes_out, R_calc_point_p2);
        }
        else {
            // s * Bv
            ge_scalarmult.ge_scalarmult(sB, s_scalar, B_point);

            // h * -K
            ge_scalarmult.ge_scalarmult(hK, h_scalar, Kneg_point);

            // R = sB - hK
            ge_p3_add.ge_p3_add(R_calc_point_p3, sB, hK);
            ge_p3_tobytes(R_bytes_out, R_calc_point_p3);
        }

        if (K_point_out != null) {
            ge_neg.ge_neg(K_point_out, Kneg_point);
        }

        return 0;
    }

    /**
     *
     * @param signature_out
     * @param eddsa_25519_pubkey_bytes
     * @param eddsa_25519_privkey_scalar
     * @param msg
     * @param msg_len
     * @param random
     * @param sha512provider
     * @param customization_label
     * @param customization_label_len
     * @return 0 if success
     *        -1 otherwise
     */
    static int generalized_eddsa_25519_sign(
                  byte[] signature_out,
                  byte[] eddsa_25519_pubkey_bytes,
                  byte[] eddsa_25519_privkey_scalar,
                  byte[] msg, long msg_len,
                  byte[] random, Sha512 sha512provider,
                  byte[] customization_label, long customization_label_len)
    {
        byte[] labelset = new byte[LABELSETMAXLEN];
        long labelset_len = 0;
        byte[] R_bytes = new byte[POINTLEN];
        byte[] r_scalar = new byte[SCALARLEN];
        byte[] h_scalar = new byte[SCALARLEN];
        byte[] s_scalar = new byte[SCALARLEN];
        byte[] M_buf = new byte[(int) (msg_len + MSTART)];

        if (signature_out == null){
            zeroize_sign(r_scalar, M_buf);
            return -1;
        }
        if (signature_out.length != SIGNATURELEN){
            zeroize_sign(r_scalar, M_buf);
            return -1;
        }
        if (eddsa_25519_pubkey_bytes == null){
            zeroize_sign(r_scalar, M_buf);
            return -1;
        }
        if (eddsa_25519_privkey_scalar == null){
            zeroize_sign(r_scalar, M_buf);
            return -1;
        }
        if (msg == null){
            zeroize_sign(r_scalar, M_buf);
            return -1;
        }
        if (customization_label == null && customization_label_len != 0){
            zeroize_sign(r_scalar, M_buf);
            return -1;
        }
        if (customization_label_len > LABELMAXLEN){
            zeroize_sign(r_scalar, M_buf);
            return -1;
        }
        if (msg_len > MSGMAXLEN){
            zeroize_sign(r_scalar, M_buf);
            return -1;
        }

        System.arraycopy(msg, 0, M_buf, MSTART, (int) msg_len);

        if (labelset_new(labelset, labelset_len, LABELSETMAXLEN, null, 0,
            customization_label, customization_label_len) != 0){
            zeroize_sign(r_scalar, M_buf);
            return -1;
        }

        if (generalized_commit(R_bytes, r_scalar, labelset, labelset_len, null, 0,
                eddsa_25519_pubkey_bytes, eddsa_25519_privkey_scalar,
                random, sha512provider, M_buf, MSTART, msg_len) != 0) {
            zeroize_sign(r_scalar, M_buf);
            return -1;
        }

        if (generalized_challenge(h_scalar, labelset, labelset_len, null, 0,
                R_bytes, eddsa_25519_pubkey_bytes, M_buf, MSTART, msg_len, sha512provider) != 0){
            zeroize_sign(r_scalar, M_buf);
            return -1;
        }

        if (generalized_prove(s_scalar, r_scalar, eddsa_25519_privkey_scalar, h_scalar) != 0){
            zeroize_sign(r_scalar, M_buf);
            return -1;
        }

        System.arraycopy(R_bytes, 0, signature_out, 0, POINTLEN);
        System.arraycopy(s_scalar, 0, signature_out, POINTLEN, SCALARLEN);

        zeroize_sign(r_scalar, M_buf);
        return 0;

    }

    private static void zeroize_sign(byte[] r_scalar, byte[] M_buf){
        r_scalar = new byte[SCALARLEN];

        // Zeroize Stack:
        byte[] m = new byte[1024];

        M_buf = new byte[1];
    }
}
