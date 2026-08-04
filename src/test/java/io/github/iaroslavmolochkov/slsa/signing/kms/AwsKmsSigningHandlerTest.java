package io.github.iaroslavmolochkov.slsa.signing.kms;

import io.github.iaroslavmolochkov.slsa.aws.client.KmsClientCache;
import io.github.iaroslavmolochkov.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.slsa.signing.SigningContext;
import io.github.iaroslavmolochkov.slsa.signing.SigningHandler;
import io.github.iaroslavmolochkov.slsa.signing.dsse.DsseEnvelope;
import io.github.iaroslavmolochkov.slsa.signing.dsse.DsseService;
import io.github.iaroslavmolochkov.slsa.signing.kms.credentials.DefaultCredentialsHandler;
import io.github.iaroslavmolochkov.slsa.signing.kms.credentials.StaticCredentialsHandler;
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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AwsKmsSigningHandlerTest {

    private final DsseService dsse = new DsseService();

    @Test
    void signsSha256OfPae() throws Exception {
        byte[] sig = {9, 8, 7};
        KmsClient kms = mock(KmsClient.class);
        when(kms.sign(any(SignRequest.class))).thenReturn(SignResponse.builder()
                .keyId("arn:key").signature(SdkBytes.fromByteArray(sig))
                .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256).build());

        KmsClientCache cache = mock(KmsClientCache.class);
        when(cache.get(any(), any())).thenReturn(kms);

        SigningHandler handler = new AwsKmsSigningHandler(cache, new AwsKmsConnectionKey(), dsse,
                List.of(new DefaultCredentialsHandler(), new StaticCredentialsHandler()));
        assertEquals(SignerType.AWS_KMS, handler.type());

        Map<String, String> params = Map.of(
                SlsaParams.SIGNER, SlsaParams.SIGNER_AWS_KMS,
                SlsaParams.CREDENTIALS, SlsaParams.CREDENTIALS_DEFAULT,
                SlsaParams.KMS_KEY_ID, "arn:key",
                SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256");
        byte[] payload = "{\"_type\":\"x\"}".getBytes(StandardCharsets.UTF_8);
        DsseEnvelope envelope = handler.sign(new SigningContext(params), payload);

        assertArrayEquals(payload, Base64.getDecoder().decode(envelope.payload()));
        assertArrayEquals(sig, Base64.getDecoder().decode(envelope.signatures().get(0).sig()));

        ArgumentCaptor<SignRequest> captor = ArgumentCaptor.forClass(SignRequest.class);
        verify(kms).sign(captor.capture());
        assertEquals(MessageType.DIGEST, captor.getValue().messageType());
        assertEquals("arn:key", captor.getValue().keyId());
        byte[] expected = MessageDigest.getInstance("SHA-256")
                .digest(dsse.pae(DsseEnvelope.IN_TOTO_PAYLOAD_TYPE, payload));
        assertArrayEquals(expected, captor.getValue().message().asByteArray());
    }

    @Test
    void usesDigestMatchingTheSigningAlgorithm() throws Exception {
        KmsClient kms = mock(KmsClient.class);
        when(kms.sign(any(SignRequest.class))).thenReturn(SignResponse.builder()
                .keyId("arn:key").signature(SdkBytes.fromByteArray(new byte[]{1}))
                .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_384).build());

        KmsClientCache cache = mock(KmsClientCache.class);
        when(cache.get(any(), any())).thenReturn(kms);

        SigningHandler handler = new AwsKmsSigningHandler(cache, new AwsKmsConnectionKey(), dsse,
                List.of(new DefaultCredentialsHandler()));

        Map<String, String> params = Map.of(
                SlsaParams.SIGNER, SlsaParams.SIGNER_AWS_KMS,
                SlsaParams.CREDENTIALS, SlsaParams.CREDENTIALS_DEFAULT,
                SlsaParams.KMS_KEY_ID, "arn:key",
                SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_384");
        byte[] payload = "{}".getBytes(StandardCharsets.UTF_8);
        handler.sign(new SigningContext(params), payload);

        ArgumentCaptor<SignRequest> captor = ArgumentCaptor.forClass(SignRequest.class);
        verify(kms).sign(captor.capture());
        byte[] expected = MessageDigest.getInstance("SHA-384")
                .digest(dsse.pae(DsseEnvelope.IN_TOTO_PAYLOAD_TYPE, payload));
        assertArrayEquals(expected, captor.getValue().message().asByteArray());
    }
}
