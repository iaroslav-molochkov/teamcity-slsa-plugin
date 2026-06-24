package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.dcp.DefaultConnectionKeyHandler;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.keys.StaticConnectionKeyHandler;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.sts.AssumeRoleConnectionKeyHandler;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class ConnectionIdServiceTest {

    private final ConnectionIdService ids = new ConnectionIdService(List.of(
            new DefaultConnectionKeyHandler(), new StaticConnectionKeyHandler(), new AssumeRoleConnectionKeyHandler()));

    private UUID id(String... kv) {
        Map<String, String> map = new HashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            map.put(kv[i], kv[i + 1]);
        }
        return ids.id(new SigningContext(map));
    }

    @Test
    void deterministicForSameInputs() {
        assertEquals(
                id(SlsaParams.SIGNER, SlsaParams.SIGNER_AWS_KMS_STATIC,
                        SlsaParams.REGION, "us-east-1", SlsaParams.ACCESS_KEY_ID, "AKIA", SlsaParams.SECRET_ACCESS_KEY, "s"),
                id(SlsaParams.SIGNER, SlsaParams.SIGNER_AWS_KMS_STATIC,
                        SlsaParams.REGION, "us-east-1", SlsaParams.ACCESS_KEY_ID, "AKIA", SlsaParams.SECRET_ACCESS_KEY, "s"));
    }

    @Test
    void differsByField() {
        assertNotEquals(
                id(SlsaParams.SIGNER, SlsaParams.SIGNER_AWS_KMS_STATIC,
                        SlsaParams.REGION, "us-east-1", SlsaParams.ACCESS_KEY_ID, "AKIA", SlsaParams.SECRET_ACCESS_KEY, "s1"),
                id(SlsaParams.SIGNER, SlsaParams.SIGNER_AWS_KMS_STATIC,
                        SlsaParams.REGION, "us-east-1", SlsaParams.ACCESS_KEY_ID, "AKIA", SlsaParams.SECRET_ACCESS_KEY, "s2"));
    }

    @Test
    void avoidsConcatenationAmbiguityTrap() {
        assertNotEquals(
                id(SlsaParams.SIGNER, SlsaParams.SIGNER_AWS_KMS_STATIC,
                        SlsaParams.REGION, "a", SlsaParams.ACCESS_KEY_ID, "ab", SlsaParams.SECRET_ACCESS_KEY, "x"),
                id(SlsaParams.SIGNER, SlsaParams.SIGNER_AWS_KMS_STATIC,
                        SlsaParams.REGION, "aa", SlsaParams.ACCESS_KEY_ID, "b", SlsaParams.SECRET_ACCESS_KEY, "x"));
    }

    @Test
    void typeIsPartOfTheKey() {
        assertNotEquals(
                id(SlsaParams.SIGNER, SlsaParams.SIGNER_AWS_KMS_DEFAULT, SlsaParams.REGION, "us-east-1"),
                id(SlsaParams.SIGNER, SlsaParams.SIGNER_AWS_KMS_ASSUME_ROLE,
                        SlsaParams.REGION, "us-east-1", SlsaParams.ASSUME_ROLE_ARN, "arn:aws:iam::1:role/r"));
    }

    @Test
    void absentOptionalFieldDiffersFromPresent() {
        assertNotEquals(
                id(SlsaParams.SIGNER, SlsaParams.SIGNER_AWS_KMS_ASSUME_ROLE,
                        SlsaParams.REGION, "us-east-1", SlsaParams.ASSUME_ROLE_ARN, "arn:aws:iam::1:role/r"),
                id(SlsaParams.SIGNER, SlsaParams.SIGNER_AWS_KMS_ASSUME_ROLE,
                        SlsaParams.REGION, "us-east-1", SlsaParams.ASSUME_ROLE_ARN, "arn:aws:iam::1:role/r",
                        SlsaParams.ASSUME_ROLE_EXTERNAL_ID, "ext"));
    }
}
