package io.github.iaroslavmolochkov.slsa.signing.server;

import io.github.iaroslavmolochkov.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.slsa.provenance.Sha256Handler;
import io.github.iaroslavmolochkov.slsa.signing.SigningContext;
import jetbrains.buildServer.serverSide.InvalidProperty;
import jetbrains.buildServer.serverSide.ServerPaths;
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ServerValidatorTest {

    @Test
    void errorWhenKeyNameMissing(@TempDir Path dir) {
        List<InvalidProperty> errors = validator(dir)
                .validate(new SigningContext(Map.of(SlsaParams.SIGNER, SlsaParams.SIGNER_SERVER)));
        assertEquals(1, errors.size());
        assertEquals(SlsaParams.SERVER_KEY_NAME, errors.get(0).getPropertyName());
    }

    @Test
    void errorWhenKeyAbsentFromStore(@TempDir Path dir) {
        List<InvalidProperty> errors = validator(dir).validate(context("absent.pem"));
        assertEquals(1, errors.size());
        assertEquals(SlsaParams.SERVER_KEY_NAME, errors.get(0).getPropertyName());
    }

    @Test
    void errorWhenKeyNameEscapesStore(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("outside.pem"), ecPkcs8Pem());
        List<InvalidProperty> errors = validator(dir).validate(context("../../outside.pem"));
        assertEquals(1, errors.size());
        assertFalse(errors.get(0).getInvalidReason().contains(dir.toString()),
                "the error must not echo server paths");
    }

    @Test
    void errorWhenKeyMalformed(@TempDir Path dir) throws Exception {
        Files.writeString(keysDir(dir).resolve("bad.pem"), "-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----\n");
        List<InvalidProperty> errors = validator(dir).validate(context("bad.pem"));
        assertEquals(1, errors.size());
        assertEquals(SlsaParams.SERVER_KEY_NAME, errors.get(0).getPropertyName());
    }

    @Test
    void noErrorsForValidEcKey(@TempDir Path dir) throws Exception {
        Files.writeString(keysDir(dir).resolve("key.pem"), ecPkcs8Pem());
        assertTrue(validator(dir).validate(context("key.pem")).isEmpty());
    }

    private static ServerValidator validator(Path dir) {
        return new ServerValidator(new ServerKeyStore(new ServerPaths(dir.toFile())),
                new ServerKeyParser(new Sha256Handler()));
    }

    private static Path keysDir(Path dir) {
        Path keysDir = dir.resolve("system").resolve("pluginData").resolve("slsa").resolve("keys");
        keysDir.toFile().mkdirs();
        return keysDir;
    }

    private static SigningContext context(String keyName) {
        return new SigningContext(Map.of(SlsaParams.SIGNER, SlsaParams.SIGNER_SERVER, SlsaParams.SERVER_KEY_NAME, keyName));
    }

    private static String ecPkcs8Pem() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        byte[] pkcs8 = generator.generateKeyPair().getPrivate().getEncoded();
        String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(pkcs8);
        return "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n";
    }
}
