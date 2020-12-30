import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyAgreementSpi;
import org.junit.Test;
import util.DHUtil;
import util.IdGenerator;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class DHUtilTester {

    @Test
    public void testDH() throws NoSuchAlgorithmException {
        Sender sender = new Sender();
        Receiver receiver = new Receiver();

        sender.setReceiver(receiver);
        receiver.setSender(sender);

        sender.keyExchange();
        sender.send();

    }

    static class Sender {
        PublicKey myPublicKey;
        PrivateKey myPrivateKey;
        PublicKey otherPublicKey;

        Receiver receiver;

        DHUtil dhUtil ;
        public Sender() throws NoSuchAlgorithmException {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            var keyPair = generator.generateKeyPair();
            myPrivateKey = keyPair.getPrivate();
            myPublicKey = keyPair.getPublic();

            dhUtil = new DHUtil(myPublicKey,myPrivateKey);

        }

        public void setReceiver(Receiver receiver)
        {
            this.receiver = receiver;
        }

        public void response(String encryptedResponse, String iv)
        {
            var response = dhUtil.decrypt(encryptedResponse,iv);

            System.out.println(response);

        }

        public void keyExchange()
        {
            otherPublicKey = receiver.keyExchange(myPublicKey);
            dhUtil.setReceiverPublicKey(otherPublicKey);

        }

        public void send()
        {
            String str = "Hello from Sender" ;
            byte[] iv = new byte[128/8];
            IdGenerator.nextBytes(iv);
            var encryptedMessage = dhUtil.encrypt(str,iv);
            receiver.request(encryptedMessage, Base64.getEncoder().encodeToString(iv));

        }

    }

    static class Receiver {

        PublicKey myPublicKey;
        PrivateKey myPrivateKey;
        PublicKey otherPublicKey;
        DHUtil dhUtil ;

        public Receiver() throws NoSuchAlgorithmException {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            var keyPair = generator.generateKeyPair();
            myPrivateKey = keyPair.getPrivate();
            myPublicKey = keyPair.getPublic();
            dhUtil = new DHUtil(myPublicKey,myPrivateKey);

        }

        public PublicKey keyExchange(PublicKey otherPublicKey)
        {
            this.otherPublicKey = otherPublicKey;
            dhUtil.setReceiverPublicKey(otherPublicKey);

            return myPublicKey;
        }

        public void request(String encryptedMessage,String iv)
        {
            var request = dhUtil.decrypt(encryptedMessage,iv);
            System.out.println(request);

            byte[] iv1 = new byte[16];
            IdGenerator.nextBytes(iv1);
            String str = "Hello World from Receiver" ;
            var encryptedResponse = dhUtil.encrypt(str,iv1);

            sender.response(encryptedResponse,Base64.getEncoder().encodeToString(iv1));

        }

        Sender sender;
        public void setSender(Sender sender)
        {
            this.sender = sender;
        }

    }



}
