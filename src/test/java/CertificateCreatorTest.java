import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Test;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static util.CertificateCreator.selfSignedCert;

public class CertificateCreatorTest {

    @Test
    public void testECCertCreation() throws CertificateException, OperatorCreationException, IOException, NoSuchAlgorithmException {
        {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            KeyPair keypair = g.generateKeyPair();
            String signatureAlgorithm = "SHA256WITHECDSA";


            X509Certificate certificate = (X509Certificate) selfSignedCert(keypair, "cn=Test", signatureAlgorithm,1);

            System.out.println(certificate);
        }
    }

    @Test
    public void testRSACertCreation() throws CertificateException, OperatorCreationException, IOException, NoSuchAlgorithmException {
        {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            KeyPair keypair = g.generateKeyPair();
            String signatureAlgorithm = "SHA512WithRSA";


            X509Certificate certificate = (X509Certificate) selfSignedCert(keypair, "cn=Test", signatureAlgorithm,3);

            System.out.println(certificate);
        }
    }



}
