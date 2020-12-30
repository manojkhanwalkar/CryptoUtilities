import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Test;
import util.SignUtil;
import util.SignatureContainer;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

import static util.CertificateCreatorUtil.selfSignedCert;

public class SignUtilTester {

    @Test
    public void testSignature() throws Exception
    {
        Signer signer = new Signer();
        var message = "Hello World";
        var container = signer.sign(message);

        Verifier verifier = new Verifier();
        var verified = verifier.verify(container,message);

        assert(verified);

    }

    static class Signer {

        SignUtil util ;

        public Signer() throws NoSuchAlgorithmException, CertificateException, OperatorCreationException, IOException {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            KeyPair keypair = g.generateKeyPair();
            String signatureAlgorithm = "SHA256WITHECDSA";


            X509Certificate certificate = (X509Certificate) selfSignedCert(keypair, "cn=SignatureTest", signatureAlgorithm,1);

            util = new SignUtil(keypair.getPrivate(), certificate);
        }

        public SignatureContainer sign(String message) throws InvalidAlgorithmParameterException, SignatureException, NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException {
            return util.sign(message);


        }

    }


    static class Verifier {

        public boolean verify(SignatureContainer container, String message) throws InvalidKeySpecException, SignatureException, NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException {
            return SignUtil.verify(container,message);
        }

    }

}
