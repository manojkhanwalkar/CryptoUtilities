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

        String privateKeyFile  = filePath("blockrsakey.der");

        var privateKey2 = CryptUtil.getPrivateKeyDerFromFile(privateKeyFile,"RSA");


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




}
