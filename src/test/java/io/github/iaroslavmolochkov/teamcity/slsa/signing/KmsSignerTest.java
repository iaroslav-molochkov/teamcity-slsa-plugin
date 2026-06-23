package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.KmsSignerConfig;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.client.KmsClientCache;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.AssumeRoleAwsCredentials;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.AwsCredentialsRegistry;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.AwsCredentialsType;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.DefaultAwsCredentials;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.StaticAwsCredentials;
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

    private final AwsCredentialsRegistry credentials = new AwsCredentialsRegistry(
            List.of(new DefaultAwsCredentials(), new StaticAwsCredentials(), new AssumeRoleAwsCredentials()));
    private final KmsValidator validator = new KmsValidator(credentials);
    private final KmsConfigMapper mapper = new KmsConfigMapper();

    private List<String> errorKeys(Map<String, String> params) {
        return validator.validate(params).stream().map(InvalidProperty::getPropertyName).toList();
    }

    @Test
    void rejectsMissingRequiredFields() {
        var keys = errorKeys(Map.of());
        assertTrue(keys.contains(SlsaParams.REGION));
        assertTrue(keys.contains(SlsaParams.KMS_KEY_ID));
        assertTrue(keys.contains(SlsaParams.SIGNING_ALGORITHM));
        assertTrue(keys.contains(SlsaParams.CREDENTIALS));
    }

    @Test
    void rejectsUnknownAlgorithmAndStaticWithoutKeys() {
        var keys = errorKeys(Map.of(
                SlsaParams.REGION, "us-east-1", SlsaParams.KMS_KEY_ID, "k",
                SlsaParams.SIGNING_ALGORITHM, "NONSENSE",
                SlsaParams.CREDENTIALS, SlsaParams.CREDENTIALS_STATIC));
        assertTrue(keys.contains(SlsaParams.SIGNING_ALGORITHM));
        assertTrue(keys.contains(SlsaParams.ACCESS_KEY_ID));
        assertTrue(keys.contains(SlsaParams.SECRET_ACCESS_KEY));
    }

    @Test
    void rejectsAssumeRoleWithoutArn() {
        var keys = errorKeys(Map.of(
                SlsaParams.REGION, "us-east-1", SlsaParams.KMS_KEY_ID, "k",
                SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256",
                SlsaParams.CREDENTIALS, SlsaParams.CREDENTIALS_ASSUME_ROLE));
        assertTrue(keys.contains(SlsaParams.ASSUME_ROLE_ARN));
    }

    @Test
    void rejectsUnknownCredentialsType() {
        var keys = errorKeys(Map.of(
                SlsaParams.REGION, "us-east-1", SlsaParams.KMS_KEY_ID, "k",
                SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256",
                SlsaParams.CREDENTIALS, "bogus"));
        assertTrue(keys.contains(SlsaParams.CREDENTIALS));
    }

    private static Map<String, String> validParams() {
        return Map.of(
                SlsaParams.REGION, "us-east-1", SlsaParams.KMS_KEY_ID, "arn:key",
                SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256",
                SlsaParams.CREDENTIALS, SlsaParams.CREDENTIALS_DEFAULT);
    }

    @Test
    void mapsValidConfig() {
        assertTrue(validator.validate(validParams()).isEmpty());

        KmsSignerConfig config = mapper.map(validParams());
        assertEquals("us-east-1", config.region());
        assertEquals(SigningAlgorithmSpec.ECDSA_SHA_256, config.algorithm());
        assertEquals(AwsCredentialsType.DEFAULT, config.credentialsType());
    }

    @Test
    void resolvesAndSignsSha256OfPae() throws Exception {
        byte[] sig = {9, 8, 7};
        KmsClient kms = mock(KmsClient.class);
        when(kms.sign(any(SignRequest.class))).thenReturn(SignResponse.builder()
                .keyId("arn:key").signature(SdkBytes.fromByteArray(sig))
                .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256).build());
        KmsClientCache cache = mock(KmsClientCache.class);
        when(cache.get(any(KmsSignerConfig.class))).thenReturn(kms);

        KmsSignerResolver resolver = new KmsSignerResolver(validator, mapper, cache);
        Signer signer = resolver.resolve(validParams()).value();
        assertEquals(SignerType.AWS_KMS, signer.type());

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
