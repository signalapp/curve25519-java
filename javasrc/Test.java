package javasrc;
import java.util.Arrays;
import java.util.Random;

public class Test
{
    public static void main(String[] args) throws Exception {
        byte[] p = new byte[32];
        byte[] q = new byte[32];
        byte[] n = new byte[32];

        /* 2000 ECDH operations */
        p[0] = 100;
        n[0] = 100;
        for (int count=0; count < 1000; count++) {
            scalarmult.crypto_scalarmult(q, n, p);
            System.arraycopy(q, 0, p, 0, 32);
            scalarmult.crypto_scalarmult(q, n, p);
            System.arraycopy(q, 0, n, 0, 32);
        }
        byte[] result = new byte[]{(byte)0xce, (byte)0xb4, (byte)0x4e, (byte)0xd6, (byte)0x4a, (byte)0xd4, (byte)0xc2, (byte)0xb5, (byte)0x43, (byte)0x9d,
                                   (byte)0x25, (byte)0xde, (byte)0xb1, (byte)0x10, (byte)0xa8, (byte)0xd7, (byte)0x2e, (byte)0xb3, (byte)0xe3, (byte)0x8e, 
                                   (byte)0xf4, (byte)0x8a, (byte)0x42, (byte)0x73, (byte)0xb1, (byte)0x1b, (byte)0x4b, (byte)0x13, (byte)0x8d, (byte)0x17, (byte)0xf9, (byte)0x34};

        if (!Arrays.equals(q, result)) {
            System.out.println("ERROR!\n");
            System.exit(-1);
        }
        System.out.println("OK");

        /* 1000 Keygen */
        byte[] out = new byte[32];
        byte[] in = new byte[32];
        in[0] = 123;
        for (int count=0; count < 1000; count++) {
            curve_sigs.curve25519_keygen(out, in);
            System.arraycopy(out, 0, in, 0, 32);
        }

        byte[] result2 = new byte[]{(byte)0xa2, (byte)0x3c, (byte)0x84, (byte)0x09, (byte)0xf2, (byte)0x93, (byte)0xb4, (byte)0x42,
                                    (byte)0x6a, (byte)0xf5, (byte)0xe5, (byte)0xe7, (byte)0xca, (byte)0xee, (byte)0x22, (byte)0xa0, 
                                    (byte)0x01, (byte)0xc7, (byte)0x9a, (byte)0xca, (byte)0x1a, (byte)0xf2, (byte)0xea, (byte)0xcb, 
                                    (byte)0x4d, (byte)0xdd, (byte)0xfa, (byte)0x05, (byte)0xf8, (byte)0xbc, (byte)0x7f, (byte)0x37};

        if (!Arrays.equals(out, result2)) {
            System.out.println("ERROR!\n");
            System.exit(-1);
        }
        System.out.println("OK");

        /* Sign */ 
        byte[] msg = new byte[1000];
        byte[] sig_out = new byte[64];
        byte[] privkey = new byte[32];
        byte[] random = new byte[64];

        curve_sigs.curve25519_sign(sig_out, privkey, msg, 100, random);
        System.out.printf("\n");
        for (int c=0; c<64; c++)
            System.out.printf("%02x ", sig_out[c]);
        System.out.printf("\n");
    }
}
