package io.github.iaroslavmolochkov.slsa.signing.kms;

import io.github.iaroslavmolochkov.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.slsa.signing.SigningContext;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class AwsKmsConnectionKeyTest {

    private final AwsKmsConnectionKey key = new AwsKmsConnectionKey();

    private UUID id(String... kv) {
        Map<String, String> map = new HashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            map.put(kv[i], kv[i + 1]);
        }
        return key.id(new SigningContext(map));
    }

    private String[] staticBase(String secret) {
        return new String[]{
                SlsaParams.SIGNER, SlsaParams.SIGNER_AWS_KMS,
                SlsaParams.CREDENTIALS, SlsaParams.CREDENTIALS_STATIC,
                SlsaParams.REGION, "us-east-1",
                SlsaParams.ACCESS_KEY_ID, "AKIA", SlsaParams.SECRET_ACCESS_KEY, secret};
    }

    @Test
    void deterministicForSameInputs() {
        assertEquals(id(staticBase("s")), id(staticBase("s")));
    }

    @Test
    void differsBySecret() {
        assertNotEquals(id(staticBase("s1")), id(staticBase("s2")));
    }

    @Test
    void avoidsConcatenationAmbiguityTrap() {
        assertNotEquals(
                id(SlsaParams.SIGNER, SlsaParams.SIGNER_AWS_KMS, SlsaParams.CREDENTIALS, SlsaParams.CREDENTIALS_STATIC,
                        SlsaParams.REGION, "a", SlsaParams.ACCESS_KEY_ID, "ab", SlsaParams.SECRET_ACCESS_KEY, "x"),
                id(SlsaParams.SIGNER, SlsaParams.SIGNER_AWS_KMS, SlsaParams.CREDENTIALS, SlsaParams.CREDENTIALS_STATIC,
                        SlsaParams.REGION, "aa", SlsaParams.ACCESS_KEY_ID, "b", SlsaParams.SECRET_ACCESS_KEY, "x"));
    }

    @Test
    void credentialsMethodIsPartOfTheKey() {
        assertNotEquals(
                id(SlsaParams.SIGNER, SlsaParams.SIGNER_AWS_KMS, SlsaParams.CREDENTIALS, SlsaParams.CREDENTIALS_DEFAULT,
                        SlsaParams.REGION, "us-east-1"),
                id(staticBase("s")));
    }

    @Test
    void assumingRoleChangesTheKey() {
        assertNotEquals(
                id(SlsaParams.SIGNER, SlsaParams.SIGNER_AWS_KMS, SlsaParams.CREDENTIALS, SlsaParams.CREDENTIALS_DEFAULT,
                        SlsaParams.REGION, "us-east-1"),
                id(SlsaParams.SIGNER, SlsaParams.SIGNER_AWS_KMS, SlsaParams.CREDENTIALS, SlsaParams.CREDENTIALS_DEFAULT,
                        SlsaParams.REGION, "us-east-1",
                        SlsaParams.ASSUME_ROLE_ENABLED, "true", SlsaParams.ASSUME_ROLE_ARN, "arn:aws:iam::1:role/r"));
    }

    @Test
    void roleAppliesToStaticBaseToo() {
        String[] base = staticBase("s");
        Map<String, String> withRole = new HashMap<>();
        for (int i = 0; i < base.length; i += 2) {
            withRole.put(base[i], base[i + 1]);
        }
        withRole.put(SlsaParams.ASSUME_ROLE_ENABLED, "true");
        withRole.put(SlsaParams.ASSUME_ROLE_ARN, "arn:aws:iam::1:role/r");
        assertNotEquals(id(base), key.id(new SigningContext(withRole)));
    }

    @Test
    void absentOptionalRoleFieldDiffersFromPresent() {
        assertNotEquals(
                id(SlsaParams.SIGNER, SlsaParams.SIGNER_AWS_KMS, SlsaParams.CREDENTIALS, SlsaParams.CREDENTIALS_DEFAULT,
                        SlsaParams.REGION, "us-east-1",
                        SlsaParams.ASSUME_ROLE_ENABLED, "true", SlsaParams.ASSUME_ROLE_ARN, "arn:aws:iam::1:role/r"),
                id(SlsaParams.SIGNER, SlsaParams.SIGNER_AWS_KMS, SlsaParams.CREDENTIALS, SlsaParams.CREDENTIALS_DEFAULT,
                        SlsaParams.REGION, "us-east-1",
                        SlsaParams.ASSUME_ROLE_ENABLED, "true", SlsaParams.ASSUME_ROLE_ARN, "arn:aws:iam::1:role/r",
                        SlsaParams.ASSUME_ROLE_EXTERNAL_ID, "ext"));
    }
}
