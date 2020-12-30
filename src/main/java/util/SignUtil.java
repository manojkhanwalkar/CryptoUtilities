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


    public static boolean  verify(SignatureContainer signatureContainer, String message) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, UnsupportedEncodingException, SignatureException {

       Signature ecdsaVerify = Signature.getInstance(signatureContainer.getAlgorithm());

        PublicKey publicKey = CertUtil.getCertFromString(signatureContainer.getCertStr()).getPublicKey();

        ecdsaVerify.initVerify(publicKey);
        ecdsaVerify.update(message.getBytes("UTF-8"));
        boolean result = ecdsaVerify.verify(Base64.getDecoder().decode(signatureContainer.getSignature()));
        return result;
    }



}



