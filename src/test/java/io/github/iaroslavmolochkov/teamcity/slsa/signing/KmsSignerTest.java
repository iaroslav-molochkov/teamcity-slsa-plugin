package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.client.KmsClientCache;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.AssumeRoleKmsSignerProcessor;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.DefaultKmsSignerProcessor;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.StaticKmsSignerProcessor;
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class KmsSignerTest {

    private final KmsClientCache cache = mock(KmsClientCache.class);
    private final DefaultKmsSignerProcessor defaultProcessor = new DefaultKmsSignerProcessor(cache);
    private final StaticKmsSignerProcessor staticProcessor = new StaticKmsSignerProcessor(cache);
    private final AssumeRoleKmsSignerProcessor assumeRoleProcessor = new AssumeRoleKmsSignerProcessor(cache);

    private static List<String> keys(List<InvalidProperty> errors) {
        return errors.stream().map(InvalidProperty::getPropertyName).toList();
    }

    @Test
    void defaultRequiresKeyAndAlgorithmButNotRegion() {
        var errors = keys(defaultProcessor.validate(Map.of()));
        assertTrue(errors.contains(SlsaParams.KMS_KEY_ID));
        assertTrue(errors.contains(SlsaParams.SIGNING_ALGORITHM));
        assertFalse(errors.contains(SlsaParams.REGION), "region is optional for the default chain");
    }

    @Test
    void defaultIsValidWithoutRegion() {
        assertTrue(defaultProcessor.validate(Map.of(
                SlsaParams.KMS_KEY_ID, "k", SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256")).isEmpty());
    }

    @Test
    void rejectsUnknownAlgorithm() {
        var errors = keys(defaultProcessor.validate(Map.of(
                SlsaParams.KMS_KEY_ID, "k", SlsaParams.SIGNING_ALGORITHM, "NONSENSE")));
        assertTrue(errors.contains(SlsaParams.SIGNING_ALGORITHM));
    }

    @Test
    void staticRequiresRegionKeysAndAlgorithm() {
        var errors = keys(staticProcessor.validate(Map.of(
                SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256")));
        assertTrue(errors.contains(SlsaParams.REGION));
        assertTrue(errors.contains(SlsaParams.KMS_KEY_ID));
        assertTrue(errors.contains(SlsaParams.ACCESS_KEY_ID));
        assertTrue(errors.contains(SlsaParams.SECRET_ACCESS_KEY));
    }

    @Test
    void assumeRoleRequiresRegionAndArn() {
        var errors = keys(assumeRoleProcessor.validate(Map.of(
                SlsaParams.KMS_KEY_ID, "k", SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256")));
        assertTrue(errors.contains(SlsaParams.REGION));
        assertTrue(errors.contains(SlsaParams.ASSUME_ROLE_ARN));
    }

    @Test
    void assumeRoleRejectsNonNumericDuration() {
        var errors = keys(assumeRoleProcessor.validate(Map.of(
                SlsaParams.REGION, "us-east-1", SlsaParams.KMS_KEY_ID, "k",
                SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256",
                SlsaParams.ASSUME_ROLE_ARN, "arn:aws:iam::1:role/r",
                SlsaParams.ASSUME_ROLE_DURATION_SECONDS, "soon")));
        assertTrue(errors.contains(SlsaParams.ASSUME_ROLE_DURATION_SECONDS));
    }

    @Test
    void processBuildsKmsSignerBackedByCachedClientAndSignsSha256OfPae() throws Exception {
        byte[] sig = {9, 8, 7};
        KmsClient kms = mock(KmsClient.class);
        when(kms.sign(any(SignRequest.class))).thenReturn(SignResponse.builder()
                .keyId("arn:key").signature(SdkBytes.fromByteArray(sig))
                .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256).build());
        when(cache.get(anyString(), any())).thenReturn(kms);

        Result<Signer> result = defaultProcessor.process(Map.of(
                SlsaParams.REGION, "us-east-1", SlsaParams.KMS_KEY_ID, "arn:key",
                SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256"));
        assertTrue(result.isValid());
        Signer signer = result.value();
        assertEquals(SignerType.AWS_KMS_DEFAULT, signer.type());

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
