package io.github.iaroslavmolochkov.teamcity.slsa.signing.server;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.Sha256Handler;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
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
    void errorWhenKeyMissing() {
        List<InvalidProperty> errors = validator.validate(new SigningContext(Map.of(SlsaParams.SIGNER, SlsaParams.SIGNER_SERVER)));
        assertEquals(1, errors.size());
        assertEquals(SlsaParams.SERVER_PRIVATE_KEY, errors.get(0).getPropertyName());
    }

    @Test
    void errorWhenKeyMalformed() {
        List<InvalidProperty> errors = validator.validate(context("-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----"));
        assertEquals(1, errors.size());
        assertEquals(SlsaParams.SERVER_PRIVATE_KEY, errors.get(0).getPropertyName());
    }

    @Test
    void noErrorsForValidEcKey() throws Exception {
        assertTrue(validator.validate(context(ecPkcs8Pem())).isEmpty());
    }

    private static SigningContext context(String pem) {
        return new SigningContext(Map.of(SlsaParams.SIGNER, SlsaParams.SIGNER_SERVER, SlsaParams.SERVER_PRIVATE_KEY, pem));
    }

    private static String ecPkcs8Pem() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        byte[] pkcs8 = generator.generateKeyPair().getPrivate().getEncoded();
        String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(pkcs8);
        return "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n";
    }
}
