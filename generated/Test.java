package generated;
import java.util.Arrays;

public class Test
{
    public static void main(String[] args) {
        int[] f = new int[10];
        int[] g = new int[10];
        byte[] b1 = new byte[32];
        byte[] b2 = new byte[32];

        //b1[0] = -1;
        //b2[1] = -1;
        b1[3] = -1;
        //b1[16] = 77;

        fe_frombytes.fe_frombytes(f, b1);
        fe_tobytes.fe_tobytes(b2, f);

        if (Arrays.equals(b1, b2))
            System.out.println("equals");
        else {
            System.out.println("not equals");
            for (int count = 0; count < 10; count++) {
                System.out.println(f[count]);
            }
            for (int count = 0; count < 32; count++) {
                System.out.println("==");
                System.out.println(b1[count]);
                System.out.println(b2[count]);
            }
        }
    }
}
