import at.favre.lib.crypto.HKDF;
import org.junit.Test;
import util.AEAD;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

public class HKDFAEADTest {

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


    private static SecretKey getKey() throws NoSuchAlgorithmException {
        HKDF hkdf = HKDF.fromHmacSha256();

        String sharedSecret = "To be Changed " ;   //TODO

        byte[] staticSalt32Byte = new byte[]{(byte) 0xDA, (byte) 0xAC, 0x3E, 0x10, 0x55, (byte) 0xB5, (byte) 0xF1, 0x3E, 0x53, (byte) 0xE4, 0x70, (byte) 0xA8, 0x77, 0x79, (byte) 0x8E, 0x0A, (byte) 0x89, (byte) 0xAE, (byte) 0x96, 0x5F, 0x19, 0x5D, 0x53, 0x62, 0x58, (byte) 0x84, 0x2C, 0x09, (byte) 0xAD, 0x6E, 0x20, (byte) 0xD4};

        byte[] pseudoRandomKey = hkdf.extract(staticSalt32Byte, sharedSecret.getBytes(StandardCharsets.UTF_8));
        byte[] expandedAesKey = hkdf.expand(pseudoRandomKey, "ChaCha20-key".getBytes(StandardCharsets.UTF_8), 32);

        SecretKey key = new SecretKeySpec(expandedAesKey, "ChaCha20"); //AES-128 key

        return key;

    }


}