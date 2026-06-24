package io.github.iaroslavmolochkov.teamcity.slsa.signing.server;

import io.github.iaroslavmolochkov.teamcity.slsa.provenance.Sha256Handler;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ServerKeyParserTest {

    private static final String OPENSSL_EC_PRIVATE = """
            -----BEGIN PRIVATE KEY-----
            MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgxRaiCnOyJC2f96ft
            l5juKNBwvP5ps58o/NXzwbuEaAahRANCAAQYMAxGJAfbRHIB3gl3azUAP93sb39N
            kykDYXRVIe1A841LXfFaBLSqww1PtPLdwigLBW0JLtWMSldHDblgvwoP
            -----END PRIVATE KEY-----
            """;
    private static final String OPENSSL_EC_PUBLIC = """
            -----BEGIN PUBLIC KEY-----
            MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGDAMRiQH20RyAd4Jd2s1AD/d7G9/
            TZMpA2F0VSHtQPONS13xWgS0qsMNT7Ty3cIoCwVtCS7VjEpXRw25YL8KDw==
            -----END PUBLIC KEY-----
            """;

    private final ServerKeyParser parser = new ServerKeyParser(new Sha256Handler());

    @Test
    void derivedPublicKeyMatchesTheOneOpensslGenerated() throws Exception {
        ServerKey key = parser.parse(OPENSSL_EC_PRIVATE);
        assertArrayEquals(spki(OPENSSL_EC_PUBLIC).getEncoded(), key.publicKey().getEncoded());
        assertEquals("sha256:" + new Sha256Handler().hex(spki(OPENSSL_EC_PUBLIC).getEncoded()), key.keyId());
    }

    @Test
    void parsesEcP256AndDerivesMatchingPublicKey() throws Exception {
        KeyPair pair = ec("secp256r1");
        ServerKey key = parser.parse(pkcs8Pem(pair));

        assertEquals("SHA256withECDSA", key.signatureAlgorithm());
        assertArrayEquals(pair.getPublic().getEncoded(), key.publicKey().getEncoded());
        assertEquals("sha256:" + new Sha256Handler().hex(pair.getPublic().getEncoded()), key.keyId());
    }

    @Test
    void derivesByCurveForEcP384() throws Exception {
        assertEquals("SHA384withECDSA", parser.parse(pkcs8Pem(ec("secp384r1"))).signatureAlgorithm());
    }

    @Test
    void parsesRsaAndDerivesMatchingPublicKey() throws Exception {
        KeyPair pair = rsa();
        ServerKey key = parser.parse(pkcs8Pem(pair));

        assertEquals("SHA256withRSA", key.signatureAlgorithm());
        assertArrayEquals(pair.getPublic().getEncoded(), key.publicKey().getEncoded());
    }

    @Test
    void rejectsGarbage() {
        assertThrows(InvalidServerKeyException.class, () -> parser.parse("-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----"));
        assertThrows(InvalidServerKeyException.class, () -> parser.parse("not even pem"));
    }

    private static KeyPair ec(String curve) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(curve));
        return generator.generateKeyPair();
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static String pkcs8Pem(KeyPair pair) {
        String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(pair.getPrivate().getEncoded());
        return "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n";
    }

    private static PublicKey spki(String pem) throws Exception {
        String body = pem.replaceAll("-----BEGIN [^-]+-----", "")
                .replaceAll("-----END [^-]+-----", "")
                .replaceAll("\\s", "");
        return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(body)));
    }
}
