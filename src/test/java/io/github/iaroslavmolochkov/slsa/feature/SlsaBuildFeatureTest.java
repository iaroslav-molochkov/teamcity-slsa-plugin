package io.github.iaroslavmolochkov.slsa.feature;

import io.github.iaroslavmolochkov.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.slsa.signing.ParameterValidator;
import jetbrains.buildServer.serverSide.PropertiesProcessor;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SlsaBuildFeatureTest {

    private final SlsaBuildFeature feature = newFeature();

    private static SlsaBuildFeature newFeature() {
        PluginDescriptor descriptor = mock(PluginDescriptor.class);
        when(descriptor.getPluginResourcesPath(any())).thenReturn("path");
        ParameterValidator validator = mock(ParameterValidator.class);
        when(validator.validate(any())).thenReturn(List.of());
        return new SlsaBuildFeature(descriptor, validator);
    }

    private Map<String, String> normalize(Map<String, String> params) {
        PropertiesProcessor processor = feature.getParametersProcessor(null);
        Map<String, String> map = new HashMap<>(params);
        processor.process(map);
        return map;
    }

    @Test
    void serverSignerStripsAllAwsParameters() {
        Map<String, String> result = normalize(Map.of(
                SlsaParams.SIGNER, SlsaParams.SIGNER_SERVER,
                SlsaParams.SERVER_KEY_NAME, "key.pem",
                SlsaParams.SIGNING_ALGORITHM, "RSASSA_PSS_SHA_256",
                SlsaParams.REGION, "us-east-1",
                SlsaParams.ACCESS_KEY_ID, "AKIA",
                SlsaParams.ASSUME_ROLE_ENABLED, "false"));

        assertEquals("key.pem", result.get(SlsaParams.SERVER_KEY_NAME));
        assertFalse(result.containsKey(SlsaParams.SIGNING_ALGORITHM), "leftover KMS algorithm must be dropped");
        assertFalse(result.containsKey(SlsaParams.REGION));
        assertFalse(result.containsKey(SlsaParams.ACCESS_KEY_ID));
        assertFalse(result.containsKey(SlsaParams.ASSUME_ROLE_ENABLED));
    }

    @Test
    void defaultCredentialsStripServerStaticAndDisabledRole() {
        Map<String, String> result = normalize(Map.of(
                SlsaParams.SIGNER, SlsaParams.SIGNER_AWS_KMS,
                SlsaParams.CREDENTIALS, SlsaParams.CREDENTIALS_DEFAULT,
                SlsaParams.KMS_KEY_ID, "k", SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256",
                SlsaParams.SERVER_KEY_NAME, "leftover.pem",
                SlsaParams.ACCESS_KEY_ID, "AKIA",
                SlsaParams.ASSUME_ROLE_ENABLED, "false", SlsaParams.ASSUME_ROLE_ARN, "arn:leftover"));

        assertTrue(result.containsKey(SlsaParams.KMS_KEY_ID));
        assertTrue(result.containsKey(SlsaParams.SIGNING_ALGORITHM));
        assertTrue(result.containsKey(SlsaParams.CREDENTIALS));
        assertFalse(result.containsKey(SlsaParams.SERVER_KEY_NAME));
        assertFalse(result.containsKey(SlsaParams.ACCESS_KEY_ID), "static keys are irrelevant to the default chain");
        assertFalse(result.containsKey(SlsaParams.ASSUME_ROLE_ARN), "role fields dropped when role is disabled");
    }

    @Test
    void staticCredentialsWithAssumeRoleKeepsStaticAndRole() {
        Map<String, String> result = normalize(Map.of(
                SlsaParams.SIGNER, SlsaParams.SIGNER_AWS_KMS,
                SlsaParams.CREDENTIALS, SlsaParams.CREDENTIALS_STATIC,
                SlsaParams.KMS_KEY_ID, "k", SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256",
                SlsaParams.ACCESS_KEY_ID, "AKIA", SlsaParams.SECRET_ACCESS_KEY, "s",
                SlsaParams.ASSUME_ROLE_ENABLED, "true", SlsaParams.ASSUME_ROLE_ARN, "arn:aws:iam::1:role/r"));

        assertTrue(result.containsKey(SlsaParams.ACCESS_KEY_ID));
        assertTrue(result.containsKey(SlsaParams.SECRET_ACCESS_KEY));
        assertTrue(result.containsKey(SlsaParams.ASSUME_ROLE_ENABLED));
        assertTrue(result.containsKey(SlsaParams.ASSUME_ROLE_ARN));
    }
}
