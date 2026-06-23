package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KmsValidatorsTest {

    private final DefaultKmsValidator defaultValidator = new DefaultKmsValidator();
    private final StaticKmsValidator staticValidator = new StaticKmsValidator();
    private final AssumeRoleKmsValidator assumeRoleValidator = new AssumeRoleKmsValidator();

    private static List<String> keys(List<InvalidProperty> errors) {
        return errors.stream().map(InvalidProperty::getPropertyName).toList();
    }

    @Test
    void defaultRequiresKeyAndAlgorithmButNotRegion() {
        var errors = keys(defaultValidator.validate(Map.of()));
        assertTrue(errors.contains(SlsaParams.KMS_KEY_ID));
        assertTrue(errors.contains(SlsaParams.SIGNING_ALGORITHM));
        assertFalse(errors.contains(SlsaParams.REGION), "region is optional for the default chain");
    }

    @Test
    void defaultIsValidWithoutRegion() {
        assertTrue(defaultValidator.validate(Map.of(
                SlsaParams.KMS_KEY_ID, "k", SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256")).isEmpty());
    }

    @Test
    void rejectsUnknownAlgorithm() {
        assertTrue(keys(defaultValidator.validate(Map.of(
                SlsaParams.KMS_KEY_ID, "k", SlsaParams.SIGNING_ALGORITHM, "NONSENSE")))
                .contains(SlsaParams.SIGNING_ALGORITHM));
    }

    @Test
    void staticRequiresRegionKeysAndAlgorithm() {
        var errors = keys(staticValidator.validate(Map.of(SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256")));
        assertTrue(errors.contains(SlsaParams.REGION));
        assertTrue(errors.contains(SlsaParams.KMS_KEY_ID));
        assertTrue(errors.contains(SlsaParams.ACCESS_KEY_ID));
        assertTrue(errors.contains(SlsaParams.SECRET_ACCESS_KEY));
    }

    @Test
    void assumeRoleRequiresRegionAndArn() {
        var errors = keys(assumeRoleValidator.validate(Map.of(
                SlsaParams.KMS_KEY_ID, "k", SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256")));
        assertTrue(errors.contains(SlsaParams.REGION));
        assertTrue(errors.contains(SlsaParams.ASSUME_ROLE_ARN));
    }

    @Test
    void assumeRoleRejectsNonNumericDuration() {
        assertTrue(keys(assumeRoleValidator.validate(Map.of(
                SlsaParams.REGION, "us-east-1", SlsaParams.KMS_KEY_ID, "k",
                SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256",
                SlsaParams.ASSUME_ROLE_ARN, "arn:aws:iam::1:role/r",
                SlsaParams.ASSUME_ROLE_DURATION_SECONDS, "soon")))
                .contains(SlsaParams.ASSUME_ROLE_DURATION_SECONDS));
    }
}
