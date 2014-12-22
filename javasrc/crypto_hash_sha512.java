package javasrc;
import java.security.MessageDigest;

public class crypto_hash_sha512 {

    public static void crypto_hash_sha512(byte[] out, byte[] in, long len) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(in, 0, (int)len);
        byte[] mdbytes = md.digest();
        System.arraycopy(mdbytes, 0, out, 0, 64);
    }
}
