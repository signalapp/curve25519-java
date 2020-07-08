package org.whispersystems.curve25519.java.ed25519;

import static org.whispersystems.curve25519.java.ed25519.constants.*;

public class gen_labelset {

    static final byte[] B_bytes = {
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    };

    // signature:
    // buffer_add(byte[] in, long in_pos, long in_len, byte[] out, long out_pos, long out_len)

    /**
     * Add byte[] to buffer at pos
     * @param in
     * @param in_pos
     * @param in_len
     * @param out
     * @param out_pos
     * @param out_len
     * @pre out != null
     * @pre out_pos < out_len
     * @pre out_pos + in_len < out_len
     * @pre in != null
     * @pre in_pos < in_len
     * @return  buffer_len if success
     *          -1 otherwise
     */
    static long buffer_add(byte[] in, long in_pos, long in_len,
                           byte[] out, long out_pos, long out_len)
    {
        long count = 0;

        if (in_pos < 0)
            return -1;
        if (out == null || out_pos > out_len)
            return -1;
        if (in_pos > in_len)
            return -1;
        if (in == null && in_len != 0)
            return -1;
        if (out_len - out_pos < in_len)
            return -1;

        for (count=0; count < in_len; count++) {
            if (out_pos + count >= out_len)
                return -1;
            out[(int) (out_pos + count)] = in[(int) (in_pos+count)];
        }

        return out_pos+in_len;
    }

    //signature:
    // buffer_pad(byte[] buf, long pos, long end)

    /**
     * Pad buffer with 0 at position
     * @param buf
     * @param pos
     * @param len
     * @pre buf != null && pos < len
     * @pre pos + pad_len < len
     * @return  new buffer_len if success
     *          0 otherwise
     */
    static long buffer_pad(byte[] buf, long pos, long len, long correction)
    {
        long count = 0;
        long pad_len = 0;

        if (pos < 0)
            return -1;
        if (buf == null || pos >= len)
            return -1;

        pad_len = (BLOCKLEN - ((pos-correction) % BLOCKLEN)) % BLOCKLEN;
        if (len - pos < pad_len)
            return -1;

        for (count=0; count < pad_len; count++) {
            if (pos+count >= len)
                return -1;
            buf[(int) (pos+count)] = 0;
        }
        return pos + pad_len;
    }


    //signature:
    // labelset_new(byte[] labelset, long labelset_len, long labelset_maxlen,
    //              byte[] protocol_name, long protocol_name_len,
    //              byte[] customization_label, long customization_label_len)

    /**
     * Create new labelset from empty byte[LABELSETMAXLEN]
     * @param labelset
     * @param labelset_len
     * @param labelset_maxlen
     * @param protocol_name
     * @param protocol_name_len
     * @param customization_label
     * @param customization_label_len
     * @pre labelset != null && labelset_maxlen <= LABELSETMAXLEN
     * @pre labelset_maxlen >= 3 + protocol_name_len + customization_label_len
     * @pre (protocol_name == null && protocol_name_len <= 0) || protocol_name != null
     * @pre protocol_name_len <= LABELMAXLEN
     * @pre (customization_label == null && customization_label_len <= 0) || protocol_name != null
     * @pre customization_label_len <= LABELMAXLEN
     * @post labelset_len == 3 + protocol_name_len + customization_label_len
     * @return labelset_len
     */
    static long labelset_new(byte[] labelset, long labelset_len, long labelset_maxlen,
                             byte[] protocol_name, long protocol_name_len,
                             byte[] customization_label, long customization_label_len)
    {
        labelset_len = 0;

        if (labelset == null)
            return -1;
        if (labelset_maxlen > LABELSETMAXLEN)
            return -1;
        if (labelset_maxlen < 3 + protocol_name_len + customization_label_len)
            return -1;
        if (protocol_name == null && protocol_name_len > 0)
            return -1;
        if (customization_label == null && customization_label_len > 0)
            return -1;
        if (protocol_name_len > LABELMAXLEN)
            return -1;
        if (customization_label_len > LABELMAXLEN)
            return -1;

        long labelset_ptr = 0;
        labelset[(int) labelset_ptr++] = 2;
        labelset[(int) labelset_ptr++] = (byte) protocol_name_len;
        labelset_ptr = buffer_add(protocol_name, 0, protocol_name_len, labelset, labelset_ptr, labelset_maxlen);
        if (labelset_ptr < 0)
            return -1;
        if (labelset != null && labelset_ptr < labelset_maxlen)
            labelset[(int) labelset_ptr++] = (byte) customization_label_len;

        labelset_ptr = buffer_add(customization_label, 0, customization_label_len, labelset, labelset_ptr, labelset_maxlen);
        if (labelset_ptr < 0)
            return -1;
        if (labelset != null && labelset_ptr == 3 + protocol_name_len + customization_label_len) {

            return labelset_ptr;

        }
        return -1;
    }


    //signature:
    //labelset_add(byte[] labelset, long labelset_len, long labelset_maxlen,
    //             byte[] label, long label_len)

    /**
     * Appends new label to labelset
     * @param labelset
     * @param labelset_len
     * @param labelset_maxlen
     * @param label
     * @param label_len
     * @return labelset_len
     */
    static long labelset_add(byte[] labelset, long labelset_len, long labelset_maxlen,
                             byte[] label, long label_len)
    {
        if (labelset_len < 0)
            return -1;
        if (labelset_len > LABELSETMAXLEN || labelset_maxlen > LABELSETMAXLEN)
            return -1;
        if (labelset_len >= labelset_maxlen || labelset_len + label_len + 1 > labelset_maxlen)
            return -1;
        if (labelset_len < 3 || labelset_maxlen < 4)
            return -1;
        if (label_len > LABELMAXLEN)
            return -1;

        long labelset_ptr = labelset_len;
        labelset[0]++;
        labelset[(int) labelset_ptr++] = (byte) label_len;
        labelset_ptr = buffer_add(label, 0, label_len, labelset, labelset_ptr, labelset_maxlen);
        if (labelset_ptr < 0)
            return -1;
        if (labelset == null)
            return -1;
        if (labelset_ptr >= labelset_maxlen)
            return -1;
        if (labelset_ptr != labelset_len + 1 + label_len)
            return -1;

        return labelset_ptr;
    }

    // signature:
    // labelset_validate(byte[] labelset, long labelset_len)

    /**
     *
     * @param labelset
     * @param labelset_len
     * @return -1 => INVALID
     *          0 => VALID
     */
    static int labelset_validate(byte[] labelset, long labelset_len)
    {
        int num_labels = 0;
        int count = 0;
        int offset = 0;
        int label_len = 0;

        if (labelset == null)
            return -1;
        if (labelset_len < 3 || labelset_len > LABELSETMAXLEN)
            return -1;

        num_labels = labelset[0];
        offset = 1;
        for (count = 0; count < num_labels; count++) {
            label_len = labelset[offset];
            if (label_len > LABELMAXLEN)
                return -1;
            offset += 1 + label_len;
            if (offset > labelset_len)
                return -1;
        }
        if (offset != labelset_len)
            return -1;
        return 0;
    }


    //signature:
    //labelset_is_empty(byte[] labelset, long labelset_len)

    /**
     * Check if labelset is empty
     * @param labelset
     * @param labelset_len
     * @return bool is_empty
     */
    static boolean labelset_is_empty(byte[] labelset, long labelset_len)
    {
        if (labelset_len != 3)
            return false;
        return true;
    }

}
