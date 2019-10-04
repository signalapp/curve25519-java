package org.whispersystems.curve25519.java;

import java.nio.ByteBuffer;

public class gen_labelset {
    final static int LABELSETMAXLEN = 512;
    final static int LABELMAXLEN = 128;

    final static byte[] B_bytes = {
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    };

    public static boolean labelset_is_empty(byte[] bb) {
        return bb.length == 3;
    }

    public static boolean labelset_validate(byte[] labelset)
    {
        if (labelset == null)
            return false;
        if (labelset.length < 3 || labelset.length > LABELSETMAXLEN)
            return false;

        int num_labels = labelset[0];
        int offset = 1;
        for (int count = 0; count < num_labels; count++) {
            int label_len = labelset[offset];
            offset += 1 + label_len;
            if (offset > labelset.length)
                return false;
        }
        return offset == labelset.length;
    }


    public static byte[] labelset_new(String protocol_name,
                                      byte[] customization_label) {
        if (LABELSETMAXLEN < 3 + protocol_name.length() + customization_label.length)
            throw new IllegalArgumentException();
        if (protocol_name.length() > LABELMAXLEN)
            throw new IllegalArgumentException();
        if (customization_label.length > LABELMAXLEN)
            throw new IllegalArgumentException();

        byte[] protocol_name_bytes = protocol_name.getBytes();

        ByteBuffer byteBuffer = ByteBuffer.allocate(3 + protocol_name_bytes.length + customization_label.length);
        byteBuffer.put((byte)2);
        byteBuffer.put((byte)protocol_name_bytes.length);
        byteBuffer.put(protocol_name_bytes);
        if (byteBuffer.position() < LABELSETMAXLEN) {
            byteBuffer.put((byte)customization_label.length);
        }

        byteBuffer.put(customization_label);

        assert byteBuffer.position() == 3 + protocol_name.length() + customization_label.length;

        return byteBuffer.array();
    }

    public static byte[] labelset_add(byte[] labelset, String label)
    {
        if (labelset.length > LABELSETMAXLEN)
            throw new IllegalStateException();
        if (labelset.length >= LABELMAXLEN || labelset.length + label.length() + 1 > LABELSETMAXLEN)
            throw new IllegalStateException();
        if (labelset.length < 3 || LABELSETMAXLEN < 4)
            throw new IllegalStateException();
        if (label.length() > LABELMAXLEN)
            throw new IllegalStateException();

        ByteBuffer bb = ByteBuffer.allocate(labelset.length + label.length() + 1);
        bb.put((byte)(labelset[0]+1));
        bb.put(labelset, 1, labelset.length - 1);
        bb.put((byte)label.getBytes().length);
        bb.put(label.getBytes());

        assert bb.position() < LABELSETMAXLEN;

        return bb.array();
    }
}
