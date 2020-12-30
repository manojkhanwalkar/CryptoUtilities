import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import util.CryptUtil;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;

import static util.JSONUtil.filePath;

public class CryptTest {

    @Test
    public void testPublicKeyCreation()
    {
        String certFile  = filePath("www.example.com.cert.pem");

        var publicKey = CryptUtil.getPublicKeyFromCertFile(certFile,"RSA");

        String pubKeyStr = CryptUtil.convertPublicKeyToString(publicKey);

        var publicKey1 = CryptUtil.convertStringtoPublicKey(pubKeyStr,"RSA");

    }

    @Test
    public void testPrivateKeyCreation() throws NoSuchAlgorithmException {

        var privateKey =  KeyPairGenerator.getInstance("EC").generateKeyPair().getPrivate();

        String privateKeyStr = CryptUtil.convertPrivateKeyToString(privateKey);

        var privateKey1 = CryptUtil.convertStringtoPrivateKey(privateKeyStr,"EC");

    }

    @Test
    public void encryptAndDecryptRSA() throws NoSuchAlgorithmException {

        Provider bcProvider = new BouncyCastleProvider();
        Security.addProvider(bcProvider);

        String keyType = "RSA";

        String msg = "Hello World";
        var keyPair = KeyPairGenerator.getInstance(keyType).generateKeyPair();

        var tuple = CryptUtil.encrypt(msg,keyPair.getPublic(),keyType);
        var msg1 = CryptUtil.decrypt(tuple.message,tuple.key,keyPair.getPrivate(),keyType);

        assert(msg.equals(msg1));


    }

    @Test
    public void encryptAndDecryptEC() throws NoSuchAlgorithmException {

        Provider bcProvider = new BouncyCastleProvider();
        Security.addProvider(bcProvider);

        String keyType = "ECIES";

        String msg = "Hello World";
        var keyPair = KeyPairGenerator.getInstance(keyType).generateKeyPair();

        var tuple = CryptUtil.encrypt(msg,keyPair.getPublic(),keyType);
        var msg1 = CryptUtil.decrypt(tuple.message,tuple.key,keyPair.getPrivate(),keyType);

        assert(msg.equals(msg1));


    }

  /*
     private static final String ALGO = "SHA256withECDSA";

  PublicKey pub =  getPublicKey(extractPublicKeyFromFile("/home/manoj/IdeaProjects/phoenix/src/main/resources/idpcertificate.pem"));
        PrivateKey priv = loadPrivateKey("/home/manoj/IdeaProjects/phoenix/src/main/resources/idpprivatekey.der");

        String plainText = "Hello World from EC Public and Private keys";

        Signature ecdsaSign = Signature.getInstance(ALGO);
        ecdsaSign.initSign(priv);
        ecdsaSign.update(plainText.getBytes("UTF-8"));
        byte[] signature = ecdsaSign.sign();


        Signature ecdsaVerify = Signature.getInstance(ALGO);

        ecdsaVerify.initVerify(pub);
        ecdsaVerify.update(plainText.getBytes("UTF-8"));
        boolean result = ecdsaVerify.verify(signature);


        System.out.println(result);*/

        //TODO - tests for the CertUtil and CryptUtil classes

        //TODO - convert JOSE4J usage to Nimbus library .







}
