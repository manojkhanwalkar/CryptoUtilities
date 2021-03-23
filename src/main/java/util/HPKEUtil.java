package util;

import at.favre.lib.crypto.HKDF;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;


public class HPKEUtil {

    private PublicKey publickey;
    private PublicKey otherPublicKey;
    PrivateKey privateKey;
    KeyAgreement keyAgreement;
    byte[] sharedsecret;

    private String secretMessage;

    final Role role;

    private static final String ALGO = "ChaCha20-Poly1305";

    //CertUtil  util = new CertUtil();
    public enum Role { Sender , Receiver };

    public HPKEUtil(PublicKey publicKey , PrivateKey privateKey, PublicKey otherPublicKey , Role role) {
        this.privateKey = privateKey;
        this.publickey = publicKey;
        this.role = role;
        this.otherPublicKey = otherPublicKey;

        makeKeyExchangeParams();
    }

    public void setSecretMessage(String str)
    {

            this.secretMessage = str;

            generateSessionKey();

    }

    public void generateSessionKey()
    {
        sessionKey = generateKey()   ;
    }


    private void makeKeyExchangeParams() {
        try {

            keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(otherPublicKey, true);
            sharedsecret = keyAgreement.generateSecret();

          //  sessionKey = generateKey();

        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    SecretKey sessionKey;

    AEAD cipher = new AEAD();


    public  String encrypt(String msg, byte[] iv) {
        try {

            byte[] encVal = cipher.encrypt(msg.getBytes(StandardCharsets.UTF_8),sessionKey);

            return new String(Base64.getEncoder().encode(encVal));
        } catch (Exception  e) {
            e.printStackTrace();
        }
        return msg;
    }

    public  String decrypt(String encryptedData, String iv) {
        try {


            byte[] decordedValue = Base64.getDecoder().decode(encryptedData);
            var decValue = cipher.decrypt(decordedValue,sessionKey);

            return new String(decValue);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encryptedData;
    }





    protected SecretKey generateKey() {

      //  return new SecretKeySpec(derivKey(), ALGO);
        return new SecretKeySpec(getKeyMaterial(), ALGO);

    }


    private  byte[] getKeyMaterial() {
        HKDF hkdf = HKDF.fromHmacSha256();

        byte[] staticSalt32Byte = new byte[]{(byte) 0xDA, (byte) 0xAC, 0x3E, 0x10, 0x55, (byte) 0xB5, (byte) 0xF1, 0x3E, 0x53, (byte) 0xE4, 0x70, (byte) 0xA8, 0x77, 0x79, (byte) 0x8E, 0x0A, (byte) 0x89, (byte) 0xAE, (byte) 0x96, 0x5F, 0x19, 0x5D, 0x53, 0x62, 0x58, (byte) 0x84, 0x2C, 0x09, (byte) 0xAD, 0x6E, 0x20, (byte) 0xD4};

        byte[] pseudoRandomKey = hkdf.extract(staticSalt32Byte, sharedsecret);
        byte[] expandedAesKey = hkdf.expand(pseudoRandomKey, secretMessage.getBytes(StandardCharsets.UTF_8), 32);

        //SecretKey key = new SecretKeySpec(expandedAesKey, "ChaCha20"); //AES-128 key

        return expandedAesKey;

    }


    // message digest step to shared secret to ensure multiple keys dont derive to the same shared secret .

    byte[] derivKey() {
        try {
            MessageDigest hash = MessageDigest.getInstance("SHA-256");
            hash.update(sharedsecret);
            // Simple deterministic ordering
            List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(publickey.getEncoded()), ByteBuffer.wrap(otherPublicKey.getEncoded()));
            Collections.sort(keys);
            hash.update(keys.get(0));
            hash.update(keys.get(1));

            byte[] derivedKey = hash.digest();

            return derivedKey;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return null;
    }







}