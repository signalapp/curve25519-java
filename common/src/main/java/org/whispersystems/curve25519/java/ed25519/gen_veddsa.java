package org.whispersystems.curve25519.java.ed25519;

import org.whispersystems.curve25519.java.*;

import static org.whispersystems.curve25519.java.ed25519.constants.*;
import static org.whispersystems.curve25519.java.ed25519.gen_eddsa.*;
import static org.whispersystems.curve25519.java.ed25519.gen_labelset.*;


public class gen_veddsa {

    /**
     *
     * @param Bv_point
     * @param labelset
     * @param labelset_len
     * @param K_bytes
     * @param M_buf
     * @param M_start
     * @param M_len
     * @param sha512provider
     * @return  0 if success
     *         -1 otherwise
     */
    public static int generalized_calculate_Bv(ge_p3 Bv_point,
                                               byte[] labelset, long labelset_len, byte[] K_bytes,
                                               byte[] M_buf, long M_start, long M_len,
                                               Sha512 sha512provider)
    {
        long prefix_len = 0;

        if (labelset_validate(labelset, labelset_len) != 0)
            return -1;
        if (Bv_point == null || K_bytes == null || M_buf == null)
            return -1;

        prefix_len = 2*POINTLEN + labelset_len;
        if (prefix_len > M_start)
            return -1;

        long M_buf_ptr = M_start - prefix_len;
        // buffer_add signature:
        // buffer_add(byte[] src, srcpos, src_len, byte[] dest, dest_pos, dest_len)
        M_buf_ptr = buffer_add(B_bytes, 0, POINTLEN, M_buf, M_buf_ptr, M_start);
        M_buf_ptr = buffer_add(labelset, 0, labelset_len, M_buf, M_buf_ptr, M_start);
        M_buf_ptr = buffer_add(K_bytes, 0, POINTLEN, M_buf, M_buf_ptr, M_start);
        if (M_buf_ptr < 0 || M_buf_ptr != M_start)
            return -1;

        //elligator.hash_to_point signature:
        // hash_to_point(ge_p3 out, byte[] in, in_pos, in_len)
        byte[] M_buf_start_prefix_len = new byte[(int) (prefix_len + M_len)];
        System.arraycopy(M_buf, (int)(M_start - prefix_len), M_buf_start_prefix_len, 0, (int)(M_len + prefix_len));

        if (elligator.hash_to_point(Bv_point, M_buf_start_prefix_len, prefix_len + M_len, sha512provider) != 0)
            return -1;
        if (ge_isneutral.ge_isneutral(Bv_point) == 1)
            return -1;

        return 0;
    }

    /**
     *
     * @param vrf_output
     * @param labelset
     * @param labelset_len
     * @param cKv_point
     * @param sha512provider
     * @pre vrf_output.len == VRFOUTPUTLEN
     * @return  0 if success
     *         -1 otherwise
     */
    static int generalized_calculate_vrf_output(byte[] vrf_output,
                                                byte[] labelset, long labelset_len,
                                                ge_p3 cKv_point,
                                                Sha512 sha512provider)
    {
        if (vrf_output.length != VRFOUTPUTLEN)
            return -1;

        byte[] buf = new byte[(int) BUFLEN];
        long buflen = BUFLEN;
        byte[] cKv_bytes = new byte[(int) POINTLEN];
        byte[] hash = new byte[(int) HASHLEN];

        if (vrf_output == null)
            return -1;

        if (labelset_len + 2*POINTLEN > BUFLEN)
            return -1;
        if (labelset_validate(labelset, labelset_len) != 0)
            return -1;
        if (cKv_point == null)
            return -1;
        if (VRFOUTPUTLEN > HASHLEN)
            return -1;

        ge_p3_tobytes.ge_p3_tobytes(cKv_bytes, cKv_point);
        long bufptr = 0;
        bufptr = buffer_add(B_bytes, 0, POINTLEN, buf, bufptr, buflen);
        bufptr = buffer_add(labelset, 0, labelset_len, buf, bufptr, buflen);
        bufptr = buffer_add(cKv_bytes, 0, POINTLEN, buf, bufptr, buflen);
        if (bufptr < 0)
            return -1;
        if (bufptr > BUFLEN)
            return -1;
        sha512provider.calculateDigest(hash, buf, bufptr);
        System.arraycopy(hash, 0, vrf_output, 0, (int) VRFOUTPUTLEN);

        return 0;
    }



    static int generalized_veddsa_25519_sign(byte[] signature_out,
                                             byte[] eddsa_25519_pubkey_bytes, byte[] eddsa_25519_privkey_scalar,
                                             byte[] msg, long msg_len,
                                             byte[] random, Sha512 sha512provider,
                                             byte[] customization_label, long customization_label_len)
    {
        byte[] labelset = new byte[(int) LABELSETMAXLEN];
        long labelset_len = 0;
        ge_p3 Bv_point = new ge_p3();
        ge_p3 Kv_point = new ge_p3();
        ge_p3 Rv_point = new ge_p3();
        byte[] Bv_bytes = new byte[(int) POINTLEN];
        byte[] Kv_bytes = new byte[(int) POINTLEN];
        byte[] Rv_bytes = new byte[(int) POINTLEN];
        byte[] R_bytes = new byte[(int) POINTLEN];
        byte[] r_scalar = new byte[(int) SCALARLEN];
        byte[] h_scalar = new byte[(int) SCALARLEN];
        byte[] s_scalar = new byte[(int) SCALARLEN];
        byte[] extra = new byte[(int) (3*POINTLEN)];
        byte[] M_buf = new byte[(int) (msg_len + MSTART)];
        byte[] protocol_name = "VEdDSA_25519_SHA512_Elligator2".getBytes();

        if (signature_out == null || signature_out.length != VRFSIGNATURELEN) {
            zeroize_sign(r_scalar, M_buf);
            return -1;
        }
        if (eddsa_25519_pubkey_bytes == null) {
            zeroize_sign(r_scalar, M_buf);
            return -1;
        }
        if (eddsa_25519_privkey_scalar == null) {
            zeroize_sign(r_scalar, M_buf);
            return -1;
        }
        if (msg == null) {
            zeroize_sign(r_scalar, M_buf);
            return -1;
        }

        if (customization_label == null && customization_label_len != 0) {
            zeroize_sign(r_scalar, M_buf);
            return -1;
        }
        if (customization_label_len > LABELMAXLEN) {
            zeroize_sign(r_scalar, M_buf);
            return -1;
        }
        if (msg_len > MSGMAXLEN) {
            zeroize_sign(r_scalar, M_buf);
            return -1;
        }

        System.arraycopy(msg, 0, M_buf, (int) MSTART, (int) msg_len);

        labelset_len = labelset_new(labelset, labelset_len, LABELMAXLEN,
                                    protocol_name, protocol_name.length,
                                    customization_label, customization_label_len);
        if (labelset_len < 0) {
            zeroize_sign(r_scalar, M_buf);
            return -1;
        }

        labelset_len = labelset_add(labelset, labelset_len, LABELSETMAXLEN, "1".getBytes(), 1);
        if (labelset_len < 0) {
            zeroize_sign(r_scalar, M_buf);
            return -1;
        }

        if (generalized_calculate_Bv(Bv_point, labelset, labelset_len,
            eddsa_25519_pubkey_bytes, M_buf, MSTART, msg_len, sha512provider) != 0)
        {
            zeroize_sign(r_scalar, M_buf);
            return -1;
        }

        ge_scalarmult.ge_scalarmult(Kv_point, eddsa_25519_privkey_scalar, Bv_point);
        ge_p3_tobytes.ge_p3_tobytes(Bv_bytes, Bv_point);
        ge_p3_tobytes.ge_p3_tobytes(Kv_bytes, Kv_point);

        labelset[(int) (labelset_len-1)] = "2".getBytes()[0];
        System.arraycopy(Bv_bytes, 0, extra, 0, (int) POINTLEN);
        System.arraycopy(Kv_bytes, 0, extra, (int) POINTLEN, (int) POINTLEN);

        if (generalized_commit(R_bytes, r_scalar,
                                         labelset, labelset_len,
                                         extra, 2*POINTLEN,
                                         eddsa_25519_pubkey_bytes, eddsa_25519_privkey_scalar,
                                         random, sha512provider,
                                         M_buf, MSTART, msg_len) != 0)
        {
            zeroize_sign(r_scalar, M_buf);
            return -1;
        }

        ge_scalarmult.ge_scalarmult(Rv_point, r_scalar, Bv_point);
        ge_p3_tobytes.ge_p3_tobytes(Rv_bytes, Rv_point);

        labelset[(int) (labelset_len-1)] = 3;
        System.arraycopy(Rv_bytes, 0, extra, (int)(2*POINTLEN), (int) (POINTLEN));
        if (generalized_challenge(h_scalar,
                                  labelset, labelset_len,
                                  extra, 3*POINTLEN,
                                  R_bytes, eddsa_25519_pubkey_bytes,
                                  M_buf, MSTART, msg_len,
                                  sha512provider) != 0)
        {
            zeroize_sign(r_scalar, M_buf);
            return -1;
        }

        if (generalized_prove(s_scalar, r_scalar, eddsa_25519_privkey_scalar, h_scalar) != 0) {
            zeroize_sign(r_scalar, M_buf);
            return -1;
        }

        //  return (Kv || h || s)
        System.arraycopy(Kv_bytes, 0, signature_out, 0, (int) POINTLEN);
        System.arraycopy(h_scalar, 0, signature_out, (int) POINTLEN, (int) SCALARLEN);
        System.arraycopy(s_scalar, 0, signature_out, POINTLEN+SCALARLEN, SCALARLEN);

        zeroize_sign(r_scalar, M_buf);
        return 0;

    }

    /**
     * Zeroize all arrays used in generalized_veddsa_25519_sign
     * @param r_scalar
     * @param M_buf
     */
    private static void zeroize_sign(byte[] r_scalar, byte[] M_buf){
        byte[] zero = new byte[SCALARLEN]; //ZEROIZE r_scalar
        System.arraycopy(zero, 0, r_scalar, 0, SCALARLEN);
        byte[] m = new byte[1024]; //ZEROIZE STACK;
        M_buf = new byte[1]; //Free M_buf
    }


    /**
     *
     * @param vrf_out
     * @param signature
     * @param eddsa_25519_pubkey_bytes
     * @param msg
     * @param msg_len
     * @param customization_label
     * @param customization_label_len
     * @param sha512provider
     * @return -1 if not successful
     *          0 if success
     */
    static int generalized_veddsa_25519_verify(byte[] vrf_out,
                  byte[] signature,
                  byte[] eddsa_25519_pubkey_bytes,
                  byte[] msg, long msg_len,
                  byte[] customization_label, long customization_label_len,
                  Sha512 sha512provider)
    {
        byte[] labelset = new byte[LABELSETMAXLEN];
        long labelset_len = 0;
        byte[] Kv_bytes = new byte[POINTLEN];
        byte[] h_scalar = new byte[SCALARLEN];
        byte[] s_scalar = new byte[SCALARLEN];
        ge_p3 Bv_point = new ge_p3(), K_point = new ge_p3(), Kv_point = new ge_p3(), cK_point = new ge_p3(), cKv_point = new ge_p3();
        byte[] Bv_bytes = new byte[POINTLEN];
        byte[] R_calc_bytes = new byte[POINTLEN];
        byte[] Rv_calc_bytes = new byte[POINTLEN];
        byte[] h_calc_scalar = new byte[SCALARLEN];
        byte[] extra = new byte[3*POINTLEN];
        byte[] M_buf = new byte[(int) (msg_len + MSTART)];
        byte[] protocol_name = "VEdDSA_25519_SHA512_Elligator2".getBytes();

        if (vrf_out == null){
            zeroize_verify(M_buf);
            return -1;
        }
        if (vrf_out.length != VRFOUTPUTLEN){
            zeroize_verify(M_buf);
            return -1;
        }
        if (signature == null){
            zeroize_verify(M_buf);
            return -1;
        }
        if (eddsa_25519_pubkey_bytes == null){
            zeroize_verify(M_buf);
            return -1;
        }
        if (msg == null){
            zeroize_verify(M_buf);
            return -1;
        }
        if (customization_label == null && customization_label_len != 0){
            zeroize_verify(M_buf);
            return -1;
        }
        if (customization_label_len > LABELMAXLEN){
            zeroize_verify(M_buf);
            return -1;
        }
        if (msg_len > MSGMAXLEN){
            zeroize_verify(M_buf);
            return -1;
        }

        System.arraycopy(msg, 0, M_buf, MSTART, (int) msg_len);

        System.arraycopy(signature, 0, Kv_bytes, 0, POINTLEN);
        System.arraycopy(signature, POINTLEN, h_scalar, 0, SCALARLEN);
        System.arraycopy(signature, POINTLEN+SCALARLEN, s_scalar, 0, SCALARLEN);

        if (!point_isreduced.point_isreduced(eddsa_25519_pubkey_bytes)){
            zeroize_verify(M_buf);
            return -1;
        }
        if (!point_isreduced.point_isreduced(Kv_bytes)){
            zeroize_verify(M_buf);
            return -1;
        }
        if (!sc_isreduced.sc_isreduced(h_scalar)){
            zeroize_verify(M_buf);
            return -1;
        }
        if (!sc_isreduced.sc_isreduced(s_scalar)){
            zeroize_verify(M_buf);
            return -1;
        }

        labelset_len = labelset_new(labelset, labelset_len, LABELSETMAXLEN,
                protocol_name, protocol_name.length,
                customization_label, customization_label_len);
        if (labelset_len < 0) {
            zeroize_verify(M_buf);
            return -1;
        }

        labelset_len = labelset_add(labelset, labelset_len, LABELSETMAXLEN, "1".getBytes(), 1);
        if (labelset_len < 0){
            zeroize_verify(M_buf);
            return -1;
        }

        if (generalized_calculate_Bv(Bv_point, labelset, labelset_len,
            eddsa_25519_pubkey_bytes, M_buf, MSTART, msg_len, sha512provider) != 0)
        {
            zeroize_verify(M_buf);
            return -1;
        }

        ge_p3_tobytes.ge_p3_tobytes(Bv_bytes, Bv_point);

        //  R = solve_commitment(B, s, K, h)
        if (generalized_solve_commitment(R_calc_bytes, K_point, null,
            s_scalar, eddsa_25519_pubkey_bytes, h_scalar) != 0)
        {
            zeroize_verify(M_buf);
            return -1;
        }


        //  Rv = solve_commitment(Bv, s, Kv, h)
        if (generalized_solve_commitment(Rv_calc_bytes, Kv_point, Bv_point,
            s_scalar, Kv_bytes, h_scalar) != 0)
        {
            zeroize_verify(M_buf);
            return -1;
        }


        ge_scalarmult_cofactor.ge_scalarmult_cofactor(cK_point, K_point);
        ge_scalarmult_cofactor.ge_scalarmult_cofactor(cKv_point, Kv_point);
        if (ge_isneutral.ge_isneutral(cK_point) == 1 || ge_isneutral.ge_isneutral(cKv_point) == 1 ||
                ge_isneutral.ge_isneutral(Bv_point) == 1)
        {
            zeroize_verify(M_buf);
            return -1;
        }

        //  labelset3 = add_label(labels, "3")
        //  h = challenge(labelset3, (Bv || Kv || Rv), R, K, M)
        labelset[(int) (labelset_len-1)] = 3;

        System.arraycopy(Bv_bytes, 0, extra, 0, POINTLEN);
        System.arraycopy(Kv_bytes, 0, extra, POINTLEN, POINTLEN);
        System.arraycopy(Rv_calc_bytes, 0, extra, 2*POINTLEN, POINTLEN);

        if (generalized_challenge(h_calc_scalar,
                labelset, labelset_len,
                extra, 3*POINTLEN,
                R_calc_bytes, eddsa_25519_pubkey_bytes,
                M_buf, MSTART, msg_len,
                sha512provider) != 0)
        {
            zeroize_verify(M_buf);
            return -1;
        }


        // if bytes_equal(h, h')
        if (crypto_verify_32.crypto_verify_32(h_scalar, h_calc_scalar) != 0){
            zeroize_verify(M_buf);
            return -1;
        }

        //  labelset4 = add_label(labels, "4")
        //  v = hash(labelset4 || c*Kv)
        labelset[(int) (labelset_len-1)] = 4;
        if (generalized_calculate_vrf_output(vrf_out, labelset, labelset_len, cKv_point, sha512provider) != 0){
            zeroize_verify(M_buf);
            return -1;
        }

        zeroize_verify(M_buf);
        return 0;
    }

    private static void zeroize_verify(byte[] M_buf){
        M_buf = new byte[1];
    }
}
