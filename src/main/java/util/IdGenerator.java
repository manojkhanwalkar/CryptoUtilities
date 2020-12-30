package util;

import java.security.SecureRandom;
import java.util.UUID;

public class IdGenerator {

    static SecureRandom secureRandom = new SecureRandom();
    public static int getId()
    {
        return secureRandom.nextInt();
    }
    public static int getId(int upperBound)
    {
        return secureRandom.nextInt(upperBound);
    }
    public static int getId(int lowerBound , int upperBound)
    {
        return lowerBound + secureRandom.nextInt(upperBound-lowerBound);
    }

    public static String getUniqueId()
    {
        return UUID.randomUUID().toString();
    }

    public static void nextBytes(byte[] iv) {
        secureRandom.nextBytes(iv);
    }
}
