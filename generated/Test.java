package generated;

public class Test

{
    public static void main(String[] args) {
        int[] f = new int[4];
        int[] g = new int[4];
        int b;

        f[0] = 123;
        f[1] = 4567;
        f[2] = 89012;
        f[3] = 3456789;

        g[0] = 1111111;
        g[1] = 2222222;
        g[2] = 3333333;
        g[3] = 4444444;

        fe_cmov.fe_cmov(f, g, 0);
        for (int count = 0; count < 4; count++)
            System.out.println(f[count]);

        fe_cmov.fe_cmov(f, g, 1);
        for (int count = 0; count < 4; count++)
            System.out.println(f[count]);
    }
}
