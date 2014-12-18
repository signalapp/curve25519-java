package javasrc;
import java.util.Arrays;
import java.util.Random;

public class Test
{
    public static void main(String[] args) {
        int[] f = new int[10];
        int[] g = new int[10];
        byte[] b1 = new byte[32];
        byte[] b2 = new byte[32];

        java.util.Random random = new java.util.Random();
        for (int count = 0; count < 100000; count++) {
            random.nextBytes(b1);        
            b1[31] = 0;
            b1[31] &= 0x78;
            b1[31] |= 0x40;
            fe_frombytes.fe_frombytes(f, b1);
            fe_tobytes.fe_tobytes(b2, f);
            if (!Arrays.equals(b1, b2)) {
                System.out.println("NOT equals");
                throw new Error();
            }
        }
    }
}
