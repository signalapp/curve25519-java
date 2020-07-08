package org.whispersystems.curve25519.java.ed25519;

import org.whispersystems.curve25519.java.Sha512;

public class veddsa_sigs {

    public static int VRFsign(Sha512 sha512provider, byte[] result, byte[] privateKey, byte[] message, int message_len, byte[] random){

        byte[] customization_label = "100".getBytes();

        int ret_val = -1;

        ret_val = gen_x.generalized_xveddsa_25519_sign(result, privateKey, message, message_len, random,
                                            sha512provider, null, 0);

        return ret_val;

    }

    public static int VRFverify(Sha512 sha512provider, byte[] vrf_out, byte[] signature,
                                byte[] publicKey, byte[] message, long messagelen){

        byte[] customization_label = new byte[64];

        int ret_val = -1;

        ret_val = gen_x.generalized_xveddsa_25519_verify(vrf_out, signature, publicKey,
                message, messagelen, null, 0, sha512provider);


        return ret_val;

    }

}
