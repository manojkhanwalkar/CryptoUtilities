import com.google.common.io.Resources;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Test;
import util.CertChainValidator;

import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static util.CertUtil.getCertificate;
import static util.CertificateCreatorUtil.*;

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
            writeCertToFile(certificate,"/tmp/cert");

            certificate = readCertFromFile("/tmp/cert");

            System.out.println(certificate);

        }
    }

    private String filePath(String fileName)
    {
        URL resource = Resources.getResource(fileName);
        return resource.getPath();

    }

    @Test
    public void testCertChainValidation()
    {

        String leafCertFile = filePath("www.example.com.cert.pem");
        X509Certificate leafCert = getCertificate(leafCertFile);

        System.out.println(leafCert);

        String certChainFile = filePath("ca-chain.cert.pem");

        X509Certificate certChainCert = getCertificate(certChainFile);

        System.out.println(certChainCert);

        String rootCertFile = filePath("ca.cert.pem");

        X509Certificate rootCertificate = getCertificate(rootCertFile);

        System.out.println(rootCertificate);

        CertChainValidator certChainValidator = new CertChainValidator(rootCertFile,certChainFile);

        assert(certChainValidator.validate(leafCertFile));





    }



}
