package util;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;


public class HMACUtil {

    private static final String HMAC_SHA512 = "HmacSHA512";


    public static String calculateHMAC(String data, String key)

    {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), HMAC_SHA512);
            Mac mac = Mac.getInstance(HMAC_SHA512);
            mac.init(secretKeySpec);
            return Base64.getEncoder().encodeToString(mac.doFinal(data.getBytes()));
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

    public static void main(String[] args) throws Exception {
        String hmac = calculateHMAC("data", "key");
        System.out.println(hmac);
    }

}
