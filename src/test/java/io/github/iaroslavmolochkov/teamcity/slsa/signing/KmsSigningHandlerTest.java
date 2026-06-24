package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.dsse.DsseEnvelope;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.dsse.DsseService;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.AbstractKmsSigningHandler;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.KmsClientLoader;
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
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class KmsSigningHandlerTest {

    private record StubLoader(SignerType type, KmsClient client) implements KmsClientLoader {
        @Override
        public KmsClient load(SigningContext context) {
            return client;
        }
    }

    @Test
    void resolvesLoaderByTypeAndSignsSha256OfPae() throws Exception {
        byte[] sig = {9, 8, 7};
        KmsClient kms = mock(KmsClient.class);
        when(kms.sign(any(SignRequest.class))).thenReturn(SignResponse.builder()
                .keyId("arn:key").signature(SdkBytes.fromByteArray(sig))
                .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256).build());

        DsseService dsse = new DsseService();
        SigningHandler handler = new AbstractKmsSigningHandler(new StubLoader(SignerType.AWS_KMS_DEFAULT, kms), dsse) {
        };
        assertEquals(SignerType.AWS_KMS_DEFAULT, handler.type());

        Map<String, String> params = Map.of(
                SlsaParams.SIGNER, SlsaParams.SIGNER_AWS_KMS_DEFAULT,
                SlsaParams.KMS_KEY_ID, "arn:key",
                SlsaParams.SIGNING_ALGORITHM, "ECDSA_SHA_256");
        byte[] payload = "{\"_type\":\"x\"}".getBytes(StandardCharsets.UTF_8);
        DsseEnvelope envelope = handler.sign(new SigningContext(params), payload);

        assertArrayEquals(payload, Base64.getDecoder().decode(envelope.payload()));
        assertArrayEquals(sig, Base64.getDecoder().decode(envelope.dsseSignatures().get(0).sig()));

        ArgumentCaptor<SignRequest> captor = ArgumentCaptor.forClass(SignRequest.class);
        verify(kms).sign(captor.capture());
        assertEquals(MessageType.DIGEST, captor.getValue().messageType());
        assertEquals("arn:key", captor.getValue().keyId());
        byte[] expected = MessageDigest.getInstance("SHA-256")
                .digest(dsse.pae(DsseEnvelope.IN_TOTO_PAYLOAD_TYPE, payload));
        assertArrayEquals(expected, captor.getValue().message().asByteArray());
    }
}
