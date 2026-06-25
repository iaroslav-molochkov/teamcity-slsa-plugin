package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.Validator;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.dcp.DefaultKmsValidator;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.keys.StaticKmsValidator;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KmsValidatorsTest {

    private final DefaultKmsValidator defaultValidator = new DefaultKmsValidator();
    private final StaticKmsValidator staticValidator = new StaticKmsValidator();

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
    void staticRequiresKeysAndAlgorithm() {
        var errors = errorKeys(staticValidator, Map.of(SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256"));
        assertTrue(errors.contains(SlsaParams.KMS_KEY_ID));
        assertTrue(errors.contains(SlsaParams.ACCESS_KEY_ID));
        assertTrue(errors.contains(SlsaParams.SECRET_ACCESS_KEY));
    }

    @Test
    void staticDoesNotRequireRegion() {
        var errors = errorKeys(staticValidator, Map.of(
                SlsaParams.KMS_KEY_ID, "k", SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256",
                SlsaParams.ACCESS_KEY_ID, "AKIA", SlsaParams.SECRET_ACCESS_KEY, "secret"));
        assertFalse(errors.contains(SlsaParams.REGION), "region is optional for static credentials");
        assertTrue(errors.isEmpty());
    }

    @Test
    void roleDisabledDoesNotRequireArn() {
        var errors = errorKeys(defaultValidator, Map.of(
                SlsaParams.KMS_KEY_ID, "k", SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256"));
        assertFalse(errors.contains(SlsaParams.ASSUME_ROLE_ARN), "role ARN is irrelevant when the role is off");
    }

    @Test
    void roleEnabledRequiresArn() {
        var errors = errorKeys(defaultValidator, Map.of(
                SlsaParams.KMS_KEY_ID, "k", SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256",
                SlsaParams.ASSUME_ROLE_ENABLED, "true"));
        assertTrue(errors.contains(SlsaParams.ASSUME_ROLE_ARN));
    }

    @Test
    void roleEnabledOnStaticBaseRequiresArn() {
        var errors = errorKeys(staticValidator, Map.of(
                SlsaParams.KMS_KEY_ID, "k", SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256",
                SlsaParams.ACCESS_KEY_ID, "AKIA", SlsaParams.SECRET_ACCESS_KEY, "secret",
                SlsaParams.ASSUME_ROLE_ENABLED, "true"));
        assertTrue(errors.contains(SlsaParams.ASSUME_ROLE_ARN), "the role decorator applies to the static base too");
    }

    @Test
    void roleEnabledDoesNotRequireRegion() {
        var errors = errorKeys(defaultValidator, Map.of(
                SlsaParams.KMS_KEY_ID, "k", SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256",
                SlsaParams.ASSUME_ROLE_ENABLED, "true", SlsaParams.ASSUME_ROLE_ARN, "arn:aws:iam::1:role/r"));
        assertFalse(errors.contains(SlsaParams.REGION), "region is optional when assuming a role");
        assertTrue(errors.isEmpty());
    }

    @Test
    void roleRejectsNonNumericDuration() {
        assertTrue(errorKeys(defaultValidator, durationParams("soon"))
                .contains(SlsaParams.ASSUME_ROLE_DURATION_SECONDS));
    }

    @Test
    void roleRejectsOutOfRangeDuration() {
        assertTrue(errorKeys(defaultValidator, durationParams("100"))
                .contains(SlsaParams.ASSUME_ROLE_DURATION_SECONDS));
        assertTrue(errorKeys(defaultValidator, durationParams("99999"))
                .contains(SlsaParams.ASSUME_ROLE_DURATION_SECONDS));
    }

    @Test
    void roleAcceptsInRangeDuration() {
        assertFalse(errorKeys(defaultValidator, durationParams("3600"))
                .contains(SlsaParams.ASSUME_ROLE_DURATION_SECONDS));
    }

    @Test
    void roleAllowsAbsentDuration() {
        var errors = errorKeys(defaultValidator, Map.of(
                SlsaParams.KMS_KEY_ID, "k", SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256",
                SlsaParams.ASSUME_ROLE_ENABLED, "true", SlsaParams.ASSUME_ROLE_ARN, "arn:aws:iam::1:role/r"));
        assertFalse(errors.contains(SlsaParams.ASSUME_ROLE_DURATION_SECONDS));
    }

    private static Map<String, String> durationParams(String duration) {
        Map<String, String> params = new HashMap<>();
        params.put(SlsaParams.KMS_KEY_ID, "k");
        params.put(SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256");
        params.put(SlsaParams.ASSUME_ROLE_ENABLED, "true");
        params.put(SlsaParams.ASSUME_ROLE_ARN, "arn:aws:iam::1:role/r");
        params.put(SlsaParams.ASSUME_ROLE_DURATION_SECONDS, duration);
        return params;
    }
}
