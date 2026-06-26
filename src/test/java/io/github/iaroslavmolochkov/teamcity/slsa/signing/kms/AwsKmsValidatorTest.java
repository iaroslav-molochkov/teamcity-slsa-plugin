package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AwsKmsValidatorTest {

    private final AwsKmsValidator validator = new AwsKmsValidator();

    private List<String> errorKeys(Map<String, String> params) {
        return validator.validate(new SigningContext(params)).stream()
                .map(InvalidProperty::getPropertyName)
                .toList();
    }

    @Test
    void requiresKeyAlgorithmAndCredentialsMethod() {
        var errors = errorKeys(Map.of());
        assertTrue(errors.contains(SlsaParams.KMS_KEY_ID));
        assertTrue(errors.contains(SlsaParams.SIGNING_ALGORITHM));
        assertTrue(errors.contains(SlsaParams.CREDENTIALS), "a credentials method must be chosen");
    }

    @Test
    void rejectsUnknownCredentialsMethod() {
        assertTrue(errorKeys(Map.of(
                SlsaParams.KMS_KEY_ID, "k", SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256",
                SlsaParams.CREDENTIALS, "nonsense"))
                .contains(SlsaParams.CREDENTIALS));
    }

    @Test
    void rejectsUnknownAlgorithm() {
        assertTrue(errorKeys(Map.of(
                SlsaParams.KMS_KEY_ID, "k", SlsaParams.SIGNING_ALGORITHM, "NONSENSE",
                SlsaParams.CREDENTIALS, SlsaParams.CREDENTIALS_DEFAULT))
                .contains(SlsaParams.SIGNING_ALGORITHM));
    }

    @Test
    void rejectsRealButUnsupportedAlgorithms() {
        List<SigningAlgorithmSpec> unsupported = List.of(
                SigningAlgorithmSpec.SM2_DSA,
                SigningAlgorithmSpec.ML_DSA_SHAKE_256,
                SigningAlgorithmSpec.ED25519_SHA_512,
                SigningAlgorithmSpec.ED25519_PH_SHA_512);
        for (SigningAlgorithmSpec spec : unsupported) {
            assertTrue(errorKeys(Map.of(
                            SlsaParams.KMS_KEY_ID, "k", SlsaParams.SIGNING_ALGORITHM, spec.toString(),
                            SlsaParams.CREDENTIALS, SlsaParams.CREDENTIALS_DEFAULT))
                            .contains(SlsaParams.SIGNING_ALGORITHM),
                    spec + " is unsupported");
        }
    }

    @Test
    void defaultCredentialsValidWithoutRegionOrKeys() {
        var errors = errorKeys(Map.of(
                SlsaParams.KMS_KEY_ID, "k", SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256",
                SlsaParams.CREDENTIALS, SlsaParams.CREDENTIALS_DEFAULT));
        assertFalse(errors.contains(SlsaParams.REGION), "region is optional for the default chain");
        assertFalse(errors.contains(SlsaParams.ACCESS_KEY_ID), "access keys are irrelevant to the default chain");
        assertTrue(errors.isEmpty());
    }

    @Test
    void staticCredentialsRequireKeys() {
        var errors = errorKeys(Map.of(
                SlsaParams.KMS_KEY_ID, "k", SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256",
                SlsaParams.CREDENTIALS, SlsaParams.CREDENTIALS_STATIC));
        assertTrue(errors.contains(SlsaParams.ACCESS_KEY_ID));
        assertTrue(errors.contains(SlsaParams.SECRET_ACCESS_KEY));
    }

    @Test
    void staticCredentialsValidWithKeysAndWithoutRegion() {
        var errors = errorKeys(Map.of(
                SlsaParams.KMS_KEY_ID, "k", SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256",
                SlsaParams.CREDENTIALS, SlsaParams.CREDENTIALS_STATIC,
                SlsaParams.ACCESS_KEY_ID, "AKIA", SlsaParams.SECRET_ACCESS_KEY, "secret"));
        assertFalse(errors.contains(SlsaParams.REGION), "region is optional for static credentials");
        assertTrue(errors.isEmpty());
    }

    @Test
    void roleDisabledDoesNotRequireArn() {
        assertFalse(errorKeys(Map.of(
                SlsaParams.KMS_KEY_ID, "k", SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256",
                SlsaParams.CREDENTIALS, SlsaParams.CREDENTIALS_DEFAULT))
                .contains(SlsaParams.ASSUME_ROLE_ARN));
    }

    @Test
    void roleEnabledRequiresArn() {
        assertTrue(errorKeys(Map.of(
                SlsaParams.KMS_KEY_ID, "k", SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256",
                SlsaParams.CREDENTIALS, SlsaParams.CREDENTIALS_DEFAULT,
                SlsaParams.ASSUME_ROLE_ENABLED, "true"))
                .contains(SlsaParams.ASSUME_ROLE_ARN));
    }

    @Test
    void roleEnabledOnStaticBaseRequiresArn() {
        assertTrue(errorKeys(Map.of(
                SlsaParams.KMS_KEY_ID, "k", SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256",
                SlsaParams.CREDENTIALS, SlsaParams.CREDENTIALS_STATIC,
                SlsaParams.ACCESS_KEY_ID, "AKIA", SlsaParams.SECRET_ACCESS_KEY, "secret",
                SlsaParams.ASSUME_ROLE_ENABLED, "true"))
                .contains(SlsaParams.ASSUME_ROLE_ARN));
    }

    @Test
    void roleRejectsNonNumericDuration() {
        assertTrue(errorKeys(durationParams("soon")).contains(SlsaParams.ASSUME_ROLE_DURATION_SECONDS));
    }

    @Test
    void roleRejectsOutOfRangeDuration() {
        assertTrue(errorKeys(durationParams("100")).contains(SlsaParams.ASSUME_ROLE_DURATION_SECONDS));
        assertTrue(errorKeys(durationParams("99999")).contains(SlsaParams.ASSUME_ROLE_DURATION_SECONDS));
    }

    @Test
    void roleAcceptsInRangeDuration() {
        assertFalse(errorKeys(durationParams("3600")).contains(SlsaParams.ASSUME_ROLE_DURATION_SECONDS));
    }

    private static Map<String, String> durationParams(String duration) {
        Map<String, String> params = new HashMap<>();
        params.put(SlsaParams.KMS_KEY_ID, "k");
        params.put(SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256");
        params.put(SlsaParams.CREDENTIALS, SlsaParams.CREDENTIALS_DEFAULT);
        params.put(SlsaParams.ASSUME_ROLE_ENABLED, "true");
        params.put(SlsaParams.ASSUME_ROLE_ARN, "arn:aws:iam::1:role/r");
        params.put(SlsaParams.ASSUME_ROLE_DURATION_SECONDS, duration);
        return params;
    }
}
