package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.Validator;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.dcp.DefaultKmsValidator;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.keys.StaticKmsValidator;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.sts.AssumeRoleKmsValidator;
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

    private static List<String> errorKeys(Validator validator, Map<String, String> params) {
        return validator.validate(new SigningContext(params)).stream()
                .map(InvalidProperty::getPropertyName)
                .toList();
    }

    @Test
    void defaultRequiresKeyAndAlgorithmButNotRegion() {
        var errors = errorKeys(defaultValidator, Map.of());
        assertTrue(errors.contains(SlsaParams.KMS_KEY_ID));
        assertTrue(errors.contains(SlsaParams.SIGNING_ALGORITHM));
        assertFalse(errors.contains(SlsaParams.REGION), "region is optional for the default chain");
    }

    @Test
    void defaultIsValidWithoutRegion() {
        assertTrue(errorKeys(defaultValidator, Map.of(
                SlsaParams.KMS_KEY_ID, "k", SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256")).isEmpty());
    }

    @Test
    void rejectsUnknownAlgorithm() {
        assertTrue(errorKeys(defaultValidator, Map.of(
                SlsaParams.KMS_KEY_ID, "k", SlsaParams.SIGNING_ALGORITHM, "NONSENSE"))
                .contains(SlsaParams.SIGNING_ALGORITHM));
    }

    @Test
    void staticRequiresRegionKeysAndAlgorithm() {
        var errors = errorKeys(staticValidator, Map.of(SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256"));
        assertTrue(errors.contains(SlsaParams.REGION));
        assertTrue(errors.contains(SlsaParams.KMS_KEY_ID));
        assertTrue(errors.contains(SlsaParams.ACCESS_KEY_ID));
        assertTrue(errors.contains(SlsaParams.SECRET_ACCESS_KEY));
    }

    @Test
    void assumeRoleRequiresRegionAndArn() {
        var errors = errorKeys(assumeRoleValidator, Map.of(
                SlsaParams.KMS_KEY_ID, "k", SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256"));
        assertTrue(errors.contains(SlsaParams.REGION));
        assertTrue(errors.contains(SlsaParams.ASSUME_ROLE_ARN));
    }

    @Test
    void assumeRoleRejectsNonNumericDuration() {
        assertTrue(errorKeys(assumeRoleValidator, durationParams("soon"))
                .contains(SlsaParams.ASSUME_ROLE_DURATION_SECONDS));
    }

    @Test
    void assumeRoleRejectsOutOfRangeDuration() {
        assertTrue(errorKeys(assumeRoleValidator, durationParams("100"))
                .contains(SlsaParams.ASSUME_ROLE_DURATION_SECONDS));
        assertTrue(errorKeys(assumeRoleValidator, durationParams("99999"))
                .contains(SlsaParams.ASSUME_ROLE_DURATION_SECONDS));
    }

    @Test
    void assumeRoleAcceptsInRangeDuration() {
        assertFalse(errorKeys(assumeRoleValidator, durationParams("3600"))
                .contains(SlsaParams.ASSUME_ROLE_DURATION_SECONDS));
    }

    @Test
    void assumeRoleAllowsAbsentDuration() {
        var errors = errorKeys(assumeRoleValidator, Map.of(
                SlsaParams.REGION, "us-east-1", SlsaParams.KMS_KEY_ID, "k",
                SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256",
                SlsaParams.ASSUME_ROLE_ARN, "arn:aws:iam::1:role/r"));
        assertFalse(errors.contains(SlsaParams.ASSUME_ROLE_DURATION_SECONDS));
    }

    private static Map<String, String> durationParams(String duration) {
        return Map.of(
                SlsaParams.REGION, "us-east-1", SlsaParams.KMS_KEY_ID, "k",
                SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256",
                SlsaParams.ASSUME_ROLE_ARN, "arn:aws:iam::1:role/r",
                SlsaParams.ASSUME_ROLE_DURATION_SECONDS, duration);
    }
}
