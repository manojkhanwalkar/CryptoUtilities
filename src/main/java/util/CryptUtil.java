package util;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static java.util.Base64.getEncoder;

public class CryptUtil {

    private static final String SYM_ALGO = "AES/GCM/NoPadding";
    private static final int GCM_IV_LEN = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final SecureRandom RANDOM = new SecureRandom();

    // Plain "RSA" resolves to RSA/ECB/PKCS1Padding (PKCS#1 v1.5), which is open to padding-oracle
    // attacks. Use OAEP for RSA key wrapping; other key types (e.g. ECIES) are used as given.
    private static String asymTransformation(String keyType)
    {
        return "RSA".equalsIgnoreCase(keyType) ? "RSA/ECB/OAEPWithSHA-256AndMGF1Padding" : keyType;
    }


    private static byte[] extractPublicKeyFromFile(String fileName)
    {
        try {
            // read the whole certificate file (a single read() may return fewer bytes)
            return Files.readAllBytes(Paths.get(fileName));
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    private static PublicKey getPublicKey(byte[] bytes)
    {
        try {

            ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
            CertificateFactory fact = CertificateFactory.getInstance("X.509");
            X509Certificate cer = (X509Certificate) fact.generateCertificate(bis);
            PublicKey key = cer.getPublicKey();


       //     System.out.println(cer);
            return key;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public static String convertPublicKeyToString(PublicKey key)
    {


        // public key to bytes , bytes to public key
        String publicKeyStr= getEncoder().encodeToString(key.getEncoded());
        return publicKeyStr;

    }


    public static String convertPrivateKeyToString(PrivateKey key)
    {



        String privateKeyStr= getEncoder().encodeToString(key.getEncoded());
        return privateKeyStr;

    }


    public static PublicKey convertStringtoPublicKey(String str, String type)
    {
        try{
            byte[] byteKey = Base64.getDecoder().decode(str.getBytes());
            X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
            KeyFactory kf = KeyFactory.getInstance(type);

            return kf.generatePublic(X509publicKey);
        }
        catch(Exception e){
            e.printStackTrace();
        }

        return null;
    }


    public static PrivateKey convertStringtoPrivateKey(String str, String type)
    {
        try{
            byte[] byteKey = Base64.getDecoder().decode(str.getBytes());
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(byteKey);
            KeyFactory kf = KeyFactory.getInstance(type);
            return kf.generatePrivate(spec);

        }
        catch(Exception e){
            e.printStackTrace();
        }

        return null;
    }


    public static SymKeyStringTuple encrypt(String message, PublicKey key, String keyType)
    {
        try {
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(256); // The AES key size in number of bits
            SecretKey secKey = generator.generateKey();

            // AES-GCM (authenticated) with a fresh random IV; output is IV || ciphertext+tag.
            byte[] iv = new byte[GCM_IV_LEN];
            RANDOM.nextBytes(iv);
            Cipher cipher =  Cipher.getInstance(SYM_ALGO);
            cipher.init(Cipher.ENCRYPT_MODE, secKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] ct = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
            byte[] out = new byte[iv.length + ct.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(ct, 0, out, iv.length, ct.length);
            String encryptedMessage = Base64.getEncoder().encodeToString(out);

            Cipher cipher1 = Cipher.getInstance(asymTransformation(keyType));
            cipher1.init(Cipher.PUBLIC_KEY, key);
            String encryptedKey = Base64.getEncoder().encodeToString(cipher1.doFinal(secKey.getEncoded()));

            SymKeyStringTuple tuple = new SymKeyStringTuple();
            tuple.key = encryptedKey;
            tuple.message= encryptedMessage;

            return tuple;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        return null;
    }



    public static String decrypt(String message, String key, PrivateKey privateKey, String keyType)  {

      try {
          Cipher cipher = Cipher.getInstance(asymTransformation(keyType));
          cipher.init(Cipher.DECRYPT_MODE, privateKey);

          byte[] decryptedKey = cipher.doFinal(Base64.getDecoder().decode(key));

          SecretKey originalKey = new SecretKeySpec(decryptedKey, 0, decryptedKey.length, "AES");
          byte[] in = Base64.getDecoder().decode(message);
          if (in.length < GCM_IV_LEN + GCM_TAG_BITS / 8) {
              return null;
          }
          Cipher aesCipher = Cipher.getInstance(SYM_ALGO);
          aesCipher.init(Cipher.DECRYPT_MODE, originalKey, new GCMParameterSpec(GCM_TAG_BITS, in, 0, GCM_IV_LEN));
          byte[] bytePlainText = aesCipher.doFinal(in, GCM_IV_LEN, in.length - GCM_IV_LEN);
          String plainText = new String(bytePlainText, StandardCharsets.UTF_8);

          return plainText;
      } catch (NoSuchAlgorithmException e) {
          e.printStackTrace();
      } catch (NoSuchPaddingException e) {
          e.printStackTrace();
      } catch (InvalidKeyException e) {
          e.printStackTrace();
      } catch (IllegalBlockSizeException e) {
          e.printStackTrace();
      } catch (BadPaddingException e) {
          e.printStackTrace();
      } catch (InvalidAlgorithmParameterException | IllegalArgumentException e) {
          e.printStackTrace();
      }

      return null;

  }




    public static PublicKey getPublicKeyFromCertFile(String file,String keyType)
    {
        return getPublicKey(extractPublicKeyFromFile(file));
    }



    public static PrivateKey getPrivateKeyDerFromFile(String file, String keyType){
        try {
            // read private key DER file (fully; a single read() may return fewer bytes)
            byte[] privKeyBytes = Files.readAllBytes(Paths.get(file));

            KeyFactory kf = KeyFactory.getInstance(keyType);
            // decode private key
            PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privKeyBytes);
            PrivateKey privKey = kf.generatePrivate(privSpec);

            return privKey;
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return null;
    }





}
