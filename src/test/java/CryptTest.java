import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import util.CryptUtil;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
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
    public void testPrivateKeyCreation() throws NoSuchAlgorithmException, IOException {

        var privateKey =  KeyPairGenerator.getInstance("EC").generateKeyPair().getPrivate();

        String privateKeyStr = CryptUtil.convertPrivateKeyToString(privateKey);

        var privateKey1 = CryptUtil.convertStringtoPrivateKey(privateKeyStr,"EC");

        // Generate a throwaway RSA key and write it as PKCS#8 DER, instead of shipping a private key in the repo.
        var rsaKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPrivate();
        Path privateKeyFile = Files.createTempFile("rsakey", ".der");
        try {
            Files.write(privateKeyFile, rsaKey.getEncoded());
            var privateKey2 = CryptUtil.getPrivateKeyDerFromFile(privateKeyFile.toString(),"RSA");
            assert(privateKey2 != null && java.util.Arrays.equals(rsaKey.getEncoded(), privateKey2.getEncoded()));
        } finally {
            Files.deleteIfExists(privateKeyFile);
        }


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
