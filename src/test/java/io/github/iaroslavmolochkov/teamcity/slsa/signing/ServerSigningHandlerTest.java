package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.Sha256Handler;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.dsse.DsseEnvelope;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.dsse.DsseService;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.server.ServerKeyParser;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.server.ServerSigningHandler;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ServerSigningHandlerTest {

    private final ServerSigningHandler service =
            new ServerSigningHandler(new ServerKeyParser(new Sha256Handler()), new DsseService());

    @Test
    void signsWithSuppliedKeyAndVerifies(@TempDir Path dir) throws Exception {
        KeyPair pair = ec();
        Path keyFile = dir.resolve("key.pem");
        Files.writeString(keyFile, pkcs8Pem(pair));
        byte[] payload = "{\"_type\":\"https://in-toto.io/Statement/v1\"}".getBytes(StandardCharsets.UTF_8);

        DsseEnvelope envelope = service.sign(context(keyFile.toString()), payload);

        assertArrayEquals(payload, Base64.getDecoder().decode(envelope.payload()));
        assertEquals("sha256:" + new Sha256Handler().hex(pair.getPublic().getEncoded()),
                envelope.signatures().get(0).keyid());

        byte[] pae = new DsseService().pae(DsseEnvelope.IN_TOTO_PAYLOAD_TYPE, payload);
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(pair.getPublic());
        verifier.update(pae);
        assertTrue(verifier.verify(Base64.getDecoder().decode(envelope.signatures().get(0).sig())));
    }

    @Test
    void signsWithEd25519KeyAndVerifies(@TempDir Path dir) throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        Path keyFile = dir.resolve("ed25519.pem");
        Files.writeString(keyFile, pkcs8Pem(pair));
        byte[] payload = "{\"_type\":\"https://in-toto.io/Statement/v1\"}".getBytes(StandardCharsets.UTF_8);

        DsseEnvelope envelope = service.sign(context(keyFile.toString()), payload);

        assertArrayEquals(payload, Base64.getDecoder().decode(envelope.payload()));
        assertEquals("sha256:" + new Sha256Handler().hex(pair.getPublic().getEncoded()),
                envelope.signatures().get(0).keyid());

        byte[] pae = new DsseService().pae(DsseEnvelope.IN_TOTO_PAYLOAD_TYPE, payload);
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(pair.getPublic());
        verifier.update(pae);
        assertTrue(verifier.verify(Base64.getDecoder().decode(envelope.signatures().get(0).sig())));
    }

    private static SigningContext context(String keyPath) {
        return new SigningContext(Map.of(
                SlsaParams.SIGNER, SlsaParams.SIGNER_SERVER,
                SlsaParams.SERVER_PRIVATE_KEY_PATH, keyPath));
    }

    private static KeyPair ec() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private static String pkcs8Pem(KeyPair pair) {
        String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(pair.getPrivate().getEncoded());
        return "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n";
    }
}
