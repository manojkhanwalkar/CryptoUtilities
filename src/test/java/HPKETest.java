import lombok.SneakyThrows;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyAgreementSpi;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import util.DHUtil;
import util.HPKEUtil;
import util.IdGenerator;

import javax.crypto.Cipher;
import java.security.*;
import java.util.Base64;

import static util.AEAD.ENCRYPT_ALGO;
import static util.AEAD.getNonce;

public class HPKETest {

    static
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    @SneakyThrows
    public static String encrypt(String message , Key secKey)
    {
        Cipher cipher =  Cipher.getInstance("ECIES","BC");
        cipher.init(Cipher.ENCRYPT_MODE, secKey);
        String encryptedMessage = Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes("UTF-8")));

        return encryptedMessage;

    }

    @SneakyThrows
    public static String decrypt(String message , Key secKey)
    {
        Cipher aesCipher = Cipher.getInstance("ECIES","BC");
        aesCipher.init(Cipher.DECRYPT_MODE, secKey);
        byte[] bytePlainText = aesCipher.doFinal(Base64.getDecoder().decode(message));
        String plainText = new String(bytePlainText);

        return plainText;
    }

    @Test
    public void testHPKE() throws NoSuchAlgorithmException {
        Sender sender = new Sender();
        Receiver receiver = new Receiver();


        sender.setReceiver(receiver);
        receiver.setSender(sender);

        sender.send();

    }

    static class Sender {
        PublicKey myPublicKey;
        PrivateKey myPrivateKey;
        PublicKey otherPublicKey;

        Receiver receiver;

        HPKEUtil util ;
        public Sender() throws NoSuchAlgorithmException {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            var keyPair = generator.generateKeyPair();
            myPrivateKey = keyPair.getPrivate();
            myPublicKey = keyPair.getPublic();


        }

        public void setReceiver(Receiver receiver)
        {
            this.receiver = receiver;
            otherPublicKey = receiver.myPublicKey;
            util = new HPKEUtil(myPublicKey,myPrivateKey,otherPublicKey, HPKEUtil.Role.Sender);
        }

        public void deriveSecret(String secret)
        {
            // decrypt using private key
            String str = decrypt(secret,myPrivateKey);
            util.setSecretMessage(str);
        }

        public void response(String encryptedResponse, String iv)
        {
            var response = util.decrypt(encryptedResponse,iv);

            System.out.println(response);

        }



        public void send()
        {
            String str = "Hello from Sender" ;
            byte[] iv = getNonce();

            var encryptedMessage = util.encrypt(str,iv);
            receiver.request(encryptedMessage, Base64.getEncoder().encodeToString(iv));

        }

    }

    static class Receiver {

        PublicKey myPublicKey;
        PrivateKey myPrivateKey;
        PublicKey otherPublicKey;
        HPKEUtil util ;

        public Receiver() throws NoSuchAlgorithmException {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            var keyPair = generator.generateKeyPair();
            myPrivateKey = keyPair.getPrivate();
            myPublicKey = keyPair.getPublic();

        }


        public void request(String encryptedMessage,String iv)
        {
            var request = util.decrypt(encryptedMessage,iv);
            System.out.println(request);

            byte[] iv1 = getNonce();

            String str = "Hello World from Receiver" ;
            var encryptedResponse = util.encrypt(str,iv1);

            sender.response(encryptedResponse,Base64.getEncoder().encodeToString(iv1));

        }

        Sender sender;
        public void setSender(Sender sender)
        {
            this.sender = sender;
            otherPublicKey = sender.myPublicKey;
            util = new HPKEUtil(myPublicKey,myPrivateKey,otherPublicKey, HPKEUtil.Role.Receiver);

            String str = "This is a secret message as input to key function " + System.nanoTime();
            util.setSecretMessage(str);

            String encStr = encrypt(str,otherPublicKey);

            sender.deriveSecret(encStr);

        }

    }



}
