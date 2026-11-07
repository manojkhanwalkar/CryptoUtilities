package util;


import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;

import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;



// using the same keys for signing and key exchange - in practice a separate set of keys will be used.


public class SignUtil {


    private static final String ALGO = "SHA256withECDSA";

    private final PrivateKey privateKey;
    private final String certStr ;




    public SignUtil(PrivateKey  privateKey, X509Certificate certificate)
    {

        this.privateKey = privateKey;
       // publicKeyStr= CryptUtil.convertPublicKeyToString(publicKey);

        this.certStr = CertUtil.getCertAsString(certificate);

    }

    public synchronized SignatureContainer sign(String plainText) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, UnsupportedEncodingException, SignatureException {

        Signature ecdsaSign = Signature.getInstance(ALGO);
        ecdsaSign.initSign(privateKey);
        ecdsaSign.update(plainText.getBytes("UTF-8"));
        byte[] signature = ecdsaSign.sign();
        String sig = Base64.getEncoder().encodeToString(signature);

        SignatureContainer signatureContainer = new SignatureContainer();
        signatureContainer.setAlgorithm(ALGO);

        signatureContainer.setCertStr(certStr);
        signatureContainer.setSignature(sig);


        return signatureContainer;
    }


    /**
     * Verifies the signature against the certificate carried inside the container itself.
     *
     * @deprecated This only proves the message was signed by <em>whoever created the container</em>:
     * an attacker can sign any message with their own key and embed their own certificate.
     * Use {@link #verify(SignatureContainer, String, PublicKey)} with a key you already trust, or
     * {@link #verify(SignatureContainer, String, CertChainValidator)} to require the embedded
     * certificate to chain to a trusted CA.
     */
    @Deprecated
    public static boolean  verify(SignatureContainer signatureContainer, String message) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, UnsupportedEncodingException, SignatureException {

        X509Certificate certificate = CertUtil.getCertFromString(signatureContainer.getCertStr());
        if (certificate == null) {
            return false;
        }
        return verifySignature(signatureContainer, message, certificate.getPublicKey());
    }

    /**
     * Verifies the signature with a public key the caller already trusts. The certificate embedded in
     * the container is ignored.
     */
    public static boolean verify(SignatureContainer signatureContainer, String message, PublicKey trustedKey) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, SignatureException {

        if (trustedKey == null) {
            return false;
        }
        return verifySignature(signatureContainer, message, trustedKey);
    }

    /**
     * Verifies the signature with the certificate embedded in the container, but only after that
     * certificate has been validated against the trusted CA chain held by {@code validator}.
     */
    public static boolean verify(SignatureContainer signatureContainer, String message, CertChainValidator validator) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, SignatureException {

        X509Certificate certificate = CertUtil.getCertFromString(signatureContainer.getCertStr());
        if (certificate == null || validator == null || !validator.validate(certificate)) {
            return false;
        }
        return verifySignature(signatureContainer, message, certificate.getPublicKey());
    }

    private static boolean verifySignature(SignatureContainer signatureContainer, String message, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, SignatureException {

        // The algorithm comes from the (untrusted) container; only accept the one this class signs with.
        if (!ALGO.equalsIgnoreCase(signatureContainer.getAlgorithm()) || signatureContainer.getSignature() == null) {
            return false;
        }

        Signature ecdsaVerify = Signature.getInstance(ALGO);
        ecdsaVerify.initVerify(publicKey);
        ecdsaVerify.update(message.getBytes("UTF-8"));
        try {
            return ecdsaVerify.verify(Base64.getDecoder().decode(signatureContainer.getSignature()));
        } catch (IllegalArgumentException | SignatureException e) {
            // malformed Base64 or DER signature: treat as not verified
            return false;
        }
    }



}



