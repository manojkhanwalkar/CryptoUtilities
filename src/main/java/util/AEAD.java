package util;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

public class AEAD {

    public static final String ENCRYPT_ALGO = "ChaCha20-Poly1305";
    private static final int NONCE_LEN = 12; // 96 bits, 12 bytes
    private static final int MAC_LEN = 16;   // Poly1305 tag, 16 bytes

    // if no nonce, generate a random 12 bytes nonce
    public byte[] encrypt(byte[] pText, SecretKey key) throws Exception {
        return encrypt(pText, key, getNonce());
    }

    public byte[] encrypt(byte[] pText, SecretKey key, byte[] nonce) throws Exception {

        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);

        if (nonce == null || nonce.length != NONCE_LEN) {
            throw new IllegalArgumentException("nonce must be " + NONCE_LEN + " bytes");
        }

        // IV, initialization value with nonce. A nonce must never be reused with the same key.
        IvParameterSpec iv = new IvParameterSpec(nonce);

        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        byte[] encryptedText = cipher.doFinal(pText);

        // append nonce to the encrypted text
        byte[] output = ByteBuffer.allocate(encryptedText.length + NONCE_LEN)
                .put(encryptedText)
                .put(nonce)
                .array();

        return output;
    }

    public byte[] decrypt(byte[] cText, SecretKey key) throws Exception {

        if (cText == null || cText.length < NONCE_LEN + MAC_LEN) {
            throw new IllegalArgumentException("ciphertext too short");
        }

        ByteBuffer bb = ByteBuffer.wrap(cText);

        // split cText to get the appended nonce
        byte[] encryptedText = new byte[cText.length - NONCE_LEN];
        byte[] nonce = new byte[NONCE_LEN];
        bb.get(encryptedText);
        bb.get(nonce);

        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);

        IvParameterSpec iv = new IvParameterSpec(nonce);

        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        // decrypted text
        byte[] output = cipher.doFinal(encryptedText);

        return output;

    }

    // Nonces must be unpredictable and unique per key, so they come from a CSPRNG.
    private static final SecureRandom random = new SecureRandom();
    // 96-bit nonce (12 bytes)
    public static byte[] getNonce() {
        byte[] newNonce = new byte[NONCE_LEN];
        random.nextBytes(newNonce);
        return newNonce;
    }

}