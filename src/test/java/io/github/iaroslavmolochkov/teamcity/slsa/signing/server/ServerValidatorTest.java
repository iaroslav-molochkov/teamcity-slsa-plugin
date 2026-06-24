package io.github.iaroslavmolochkov.teamcity.slsa.signing.server;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.Sha256Handler;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ServerValidatorTest {

    private final ServerValidator validator = new ServerValidator(new ServerKeyParser(new Sha256Handler()));

    @Test
    void errorWhenPathMissing() {
        List<InvalidProperty> errors = validator.validate(new SigningContext(Map.of(SlsaParams.SIGNER, SlsaParams.SIGNER_SERVER)));
        assertEquals(1, errors.size());
        assertEquals(SlsaParams.SERVER_PRIVATE_KEY_PATH, errors.get(0).getPropertyName());
    }

    @Test
    void errorWhenPathNotAbsolute() {
        List<InvalidProperty> errors = validator.validate(context("relative/key.pem"));
        assertEquals(1, errors.size());
        assertEquals(SlsaParams.SERVER_PRIVATE_KEY_PATH, errors.get(0).getPropertyName());
    }

    @Test
    void errorWhenFileMissing(@TempDir Path dir) {
        List<InvalidProperty> errors = validator.validate(context(dir.resolve("absent.pem").toString()));
        assertEquals(1, errors.size());
        assertEquals(SlsaParams.SERVER_PRIVATE_KEY_PATH, errors.get(0).getPropertyName());
    }

    @Test
    void errorWhenFileMalformed(@TempDir Path dir) throws Exception {
        Path key = dir.resolve("bad.pem");
        Files.writeString(key, "-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----\n");
        List<InvalidProperty> errors = validator.validate(context(key.toString()));
        assertEquals(1, errors.size());
        assertEquals(SlsaParams.SERVER_PRIVATE_KEY_PATH, errors.get(0).getPropertyName());
    }

    @Test
    void noErrorsForValidEcKeyFile(@TempDir Path dir) throws Exception {
        Path key = dir.resolve("key.pem");
        Files.writeString(key, ecPkcs8Pem());
        assertTrue(validator.validate(context(key.toString())).isEmpty());
    }

    private static SigningContext context(String path) {
        return new SigningContext(Map.of(SlsaParams.SIGNER, SlsaParams.SIGNER_SERVER, SlsaParams.SERVER_PRIVATE_KEY_PATH, path));
    }

    private static String ecPkcs8Pem() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        byte[] pkcs8 = generator.generateKeyPair().getPrivate().getEncoded();
        String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(pkcs8);
        return "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n";
    }
}
