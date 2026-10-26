import org.junit.Test;
import util.AEAD;
import util.CertChainValidator;
import util.CryptUtil;
import util.DHUtil;
import util.HMACUtil;
import util.JSONUtil;
import util.SignUtil;
import util.SignatureContainer;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static util.CertificateCreatorUtil.selfSignedCert;
import static util.JSONUtil.filePath;

/** Regression tests for the OWASP Top 10 audit fixes. */
public class SecurityRegressionTest {

    private static SignUtil signer(KeyPair kp, String dn) throws Exception {
        X509Certificate cert = (X509Certificate) selfSignedCert(kp, dn, "SHA256WITHECDSA", 1);
        return new SignUtil(kp.getPrivate(), cert);
    }

    @Test
    public void forgedSignatureRejectedWithTrustedKey() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        KeyPair legit = g.generateKeyPair();
        KeyPair attacker = g.generateKeyPair();

        SignatureContainer good = signer(legit, "cn=Legit").sign("pay 10");
        SignatureContainer forged = signer(attacker, "cn=Legit").sign("pay 1000");

        assertTrue(SignUtil.verify(good, "pay 10", legit.getPublic()));
        assertFalse(SignUtil.verify(forged, "pay 1000", legit.getPublic()));
        assertFalse(SignUtil.verify(good, "pay 11", legit.getPublic()));
    }

    @Test
    public void selfSignedCertRejectedByChainValidator() throws Exception {
        KeyPair attacker = KeyPairGenerator.getInstance("EC").generateKeyPair();
        SignatureContainer forged = signer(attacker, "cn=www.test.com").sign("hello");
        CertChainValidator validator = new CertChainValidator(filePath("ca.cert.pem"), filePath("ca-chain.cert.pem"));
        assertFalse(SignUtil.verify(forged, "hello", validator));
    }

    @Test
    public void unexpectedSignatureAlgorithmRejected() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("EC").generateKeyPair();
        SignatureContainer c = signer(kp, "cn=Test").sign("hello");
        c.setAlgorithm("NONEwithECDSA");
        assertFalse(SignUtil.verify(c, "hello", kp.getPublic()));
    }

    @Test
    public void hmacValidation() {
        String mac = HMACUtil.calculateHMAC("data", "key");
        assertTrue(HMACUtil.isValid(mac, "data", "key"));
        assertFalse(HMACUtil.isValid(mac, "data2", "key"));
        assertFalse(HMACUtil.isValid(mac.substring(1), "data", "key"));
    }

    @Test
    public void aeadNoncesAreUniqueAndShortInputRejected() throws Exception {
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 1000; i++) {
            assertTrue(seen.add(Base64.getEncoder().encodeToString(AEAD.getNonce())));
        }
        SecretKey key = KeyGenerator.getInstance("ChaCha20").generateKey();
        try {
            new AEAD().decrypt(new byte[5], key);
            fail("short ciphertext must be rejected");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void dhEncryptFailsClosedWithoutSessionKey() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("EC").generateKeyPair();
        DHUtil dh = new DHUtil(kp.getPublic(), kp.getPrivate());
        try {
            String out = dh.encrypt("secret", new byte[12]);
            fail("encrypt without a session key must throw, got " + out);
        } catch (IllegalStateException expected) {
        }
    }

    @Test
    public void dhTamperedCiphertextRejected() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        KeyPair a = g.generateKeyPair();
        KeyPair b = g.generateKeyPair();
        DHUtil alice = new DHUtil(a.getPublic(), a.getPrivate());
        DHUtil bob = new DHUtil(b.getPublic(), b.getPrivate());
        alice.setReceiverPublicKey(b.getPublic());
        bob.setReceiverPublicKey(a.getPublic());

        byte[] iv = new byte[12];
        util.IdGenerator.nextBytes(iv);
        String ivStr = Base64.getEncoder().encodeToString(iv);
        String ct = alice.encrypt("hello", iv);
        assertEquals("hello", bob.decrypt(ct, ivStr));

        byte[] raw = Base64.getDecoder().decode(ct);
        raw[0] ^= 1;
        try {
            bob.decrypt(Base64.getEncoder().encodeToString(raw), ivStr);
            fail("tampered ciphertext must be rejected");
        } catch (IllegalStateException expected) {
        }
    }

    @Test
    public void cryptUtilHybridRoundTripAndTamperDetection() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        var tuple = CryptUtil.encrypt("Hello World", kp.getPublic(), "RSA");
        assertEquals("Hello World", CryptUtil.decrypt(tuple.message, tuple.key, kp.getPrivate(), "RSA"));

        byte[] raw = Base64.getDecoder().decode(tuple.message);
        raw[raw.length - 1] ^= 1;
        assertNull(CryptUtil.decrypt(Base64.getEncoder().encodeToString(raw), tuple.key, kp.getPrivate(), "RSA"));

        // identical plaintexts must not give identical ciphertexts (no ECB / IV reuse)
        var t2 = CryptUtil.encrypt("Hello World", kp.getPublic(), "RSA");
        assertFalse(Arrays.equals(Base64.getDecoder().decode(tuple.message), Base64.getDecoder().decode(t2.message)));
    }

    public static class Holder {
        public Object value;
    }

    @Test
    public void jsonDoesNotHonourAttackerSuppliedTypes() {
        String payload = "{\"value\":[\"java.util.concurrent.atomic.AtomicBoolean\",true]}";
        Holder h = (Holder) JSONUtil.fromJSON(payload, Holder.class);
        assertNotNull(h);
        assertFalse(h.value instanceof java.util.concurrent.atomic.AtomicBoolean);
    }
}
