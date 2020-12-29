package util;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;


public class HMACUtil {

    private static final String HMAC_SHA512 = "HmacSHA512";


    public static String calculateHMAC(String data, String key)
    {
        return calculateHMAC(data.getBytes(),key.getBytes());

    }

    public static byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream os = new ObjectOutputStream(bos);
        os.writeObject(obj);
        return bos.toByteArray();
    }


    public static String calculateHMAC(Object data, Object key) throws IOException
    {

        return calculateHMAC(serialize(data),serialize(key));

    }

    public static String calculateHMAC(byte[] data, byte[] key)

    {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, HMAC_SHA512);
            Mac mac = Mac.getInstance(HMAC_SHA512);
            mac.init(secretKeySpec);
            return Base64.getEncoder().encodeToString(mac.doFinal(data));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        return null;
    }


    public static boolean isValid(String hmac , String data , String key)
    {

        return hmac.equals(calculateHMAC(data,key));

    }

    public static boolean isValid(String hmac , Object data , Object key) throws IOException
    {

        return hmac.equals(calculateHMAC(data,key));

    }

    public static boolean isValid(String hmac , byte[] data , byte[] key)
    {

        return hmac.equals(calculateHMAC(data,key));

    }


    public static void main(String[] args) throws Exception {
        String hmac = calculateHMAC("data", "key");
        System.out.println(hmac);
    }

}
