import at.favre.lib.crypto.HKDF;
import org.junit.Test;
import util.AEAD;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class AEADTest {

    private static final int NONCE_LEN = 12;                    // 96 bits, 12 bytes
    private static final int MAC_LEN = 16;                      // 128 bits, 16 bytes


    @Test
    public void test() throws Exception {

        String input = "Java & ChaCha20-Poly1305.";

        AEAD cipher = new AEAD();

        SecretKey key = getKey();                               // 256-bit secret key (32 bytes)

        byte[] cText = cipher.encrypt(input.getBytes(), key);   // encrypt

        byte[] pText = cipher.decrypt(cText, key);              // decrypt


        String pTextStr = new String(pText);

        assert (input.equals(pTextStr));
    }


    // A 256-bit secret key (32 bytes)
   private static SecretKey getKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("ChaCha20");
        keyGen.init(256, SecureRandom.getInstanceStrong());
        return keyGen.generateKey();
    }



}