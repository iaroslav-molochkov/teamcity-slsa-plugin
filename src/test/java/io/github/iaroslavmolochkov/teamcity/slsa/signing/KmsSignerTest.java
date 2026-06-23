package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.KmsSignerConfig;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.client.KmsClientCache;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.AssumeRoleResolution;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.BaseCredentialsRegistry;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.CredentialsMode;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.CredentialsResolutions;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.CredentialsSource;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.DefaultCredentials;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.DirectResolution;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.StaticCredentials;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SignerConfig;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class KmsSignerTest {

    private final BaseCredentialsRegistry bases =
            new BaseCredentialsRegistry(List.of(new DefaultCredentials(), new StaticCredentials()));
    private final CredentialsResolutions resolutions =
            new CredentialsResolutions(List.of(new DirectResolution(bases), new AssumeRoleResolution(bases)));
    private final KmsValidator validator = new KmsValidator(bases, resolutions);
    private final KmsConfigMapper mapper = new KmsConfigMapper(bases, resolutions);

    private List<String> errorKeys(Map<String, String> params) {
        return validator.validate(params).stream().map(InvalidProperty::getPropertyName).toList();
    }

    @Test
    void rejectsMissingRequiredFields() {
        var keys = errorKeys(Map.of());
        assertTrue(keys.contains(SlsaParams.REGION));
        assertTrue(keys.contains(SlsaParams.KMS_KEY_ID));
        assertTrue(keys.contains(SlsaParams.SIGNING_ALGORITHM));
    }

    @Test
    void rejectsUnknownAlgorithmAndStaticWithoutKeys() {
        var keys = errorKeys(Map.of(
                SlsaParams.REGION, "us-east-1", SlsaParams.KMS_KEY_ID, "k",
                SlsaParams.SIGNING_ALGORITHM, "NONSENSE",
                SlsaParams.CREDENTIALS_SOURCE, "static"));
        assertTrue(keys.contains(SlsaParams.SIGNING_ALGORITHM));
        assertTrue(keys.contains(SlsaParams.ACCESS_KEY_ID));
        assertTrue(keys.contains(SlsaParams.SECRET_ACCESS_KEY));
    }

    @Test
    void rejectsAssumeRoleWithoutArn() {
        var keys = errorKeys(Map.of(
                SlsaParams.REGION, "us-east-1", SlsaParams.KMS_KEY_ID, "k",
                SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256",
                SlsaParams.CREDENTIALS_MODE, "assume-role"));
        assertTrue(keys.contains(SlsaParams.ASSUME_ROLE_ARN));
    }

    @Test
    void rejectsMissingBaseAndMode() {
        var keys = errorKeys(Map.of(
                SlsaParams.REGION, "us-east-1", SlsaParams.KMS_KEY_ID, "k",
                SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256"));
        assertTrue(keys.contains(SlsaParams.CREDENTIALS_SOURCE));
        assertTrue(keys.contains(SlsaParams.CREDENTIALS_MODE));
    }

    @Test
    void rejectsUnknownSourceAndMode() {
        var keys = errorKeys(Map.of(
                SlsaParams.REGION, "us-east-1", SlsaParams.KMS_KEY_ID, "k",
                SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256",
                SlsaParams.CREDENTIALS_SOURCE, "bogus",
                SlsaParams.CREDENTIALS_MODE, "bogus"));
        assertTrue(keys.contains(SlsaParams.CREDENTIALS_SOURCE));
        assertTrue(keys.contains(SlsaParams.CREDENTIALS_MODE));
    }

    private static Map<String, String> validParams() {
        return Map.of(
                SlsaParams.REGION, "us-east-1", SlsaParams.KMS_KEY_ID, "arn:key",
                SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256",
                SlsaParams.CREDENTIALS_SOURCE, SlsaParams.BASE_DEFAULT,
                SlsaParams.CREDENTIALS_MODE, SlsaParams.MODE_DIRECT);
    }

    @Test
    void mapsValidConfig() {
        assertTrue(validator.validate(validParams()).isEmpty());

        KmsSignerConfig config = (KmsSignerConfig) mapper.map(validParams());
        assertEquals("us-east-1", config.region());
        assertEquals(SigningAlgorithmSpec.ECDSA_SHA_256, config.algorithm());
        assertEquals(CredentialsSource.DEFAULT, config.source());
        assertEquals(CredentialsMode.DIRECT, config.mode());
    }

    @Test
    void signsSha256OfPae() throws Exception {
        byte[] sig = {9, 8, 7};
        KmsClient kms = mock(KmsClient.class);
        when(kms.sign(any(SignRequest.class))).thenReturn(SignResponse.builder()
                .keyId("arn:key").signature(SdkBytes.fromByteArray(sig))
                .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256).build());
        KmsClientCache cache = mock(KmsClientCache.class);
        when(cache.get(any(KmsSignerConfig.class))).thenReturn(kms);

        SignerConfig config = mapper.map(validParams());
        Signer signer = new KmsSignerFactory(cache).create(config);

        byte[] payload = "{\"_type\":\"x\"}".getBytes(StandardCharsets.UTF_8);
        DsseEnvelope envelope = signer.sign(payload);

        assertArrayEquals(payload, Base64.getDecoder().decode(envelope.payload()));
        assertArrayEquals(sig, Base64.getDecoder().decode(envelope.signatures().get(0).sig()));

        ArgumentCaptor<SignRequest> captor = ArgumentCaptor.forClass(SignRequest.class);
        verify(kms).sign(captor.capture());
        assertEquals(MessageType.DIGEST, captor.getValue().messageType());
        byte[] expected = MessageDigest.getInstance("SHA-256")
                .digest(Pae.encode(DsseEnvelope.IN_TOTO_PAYLOAD_TYPE, payload));
        assertArrayEquals(expected, captor.getValue().message().asByteArray());
    }
}
