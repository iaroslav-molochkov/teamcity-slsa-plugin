package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.client.KmsClientCache;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.client.SignerClient;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningException;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningHandler;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.dsse.DsseEnvelope;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.dsse.DsseService;
import jetbrains.buildServer.serverSide.IOGuard;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.KmsClientBuilder;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Skeletal {@link SigningHandler} for the KMS modes: caches a per-connection KMS client and signs a digest. */
public abstract class AbstractKmsSigningHandler implements SigningHandler {

    private final KmsClientCache cache;
    private final ConnectionIdService connectionIdService;
    private final DsseService dsse;

    protected AbstractKmsSigningHandler(KmsClientCache cache, ConnectionIdService connectionIdService, DsseService dsse) {
        this.cache = cache;
        this.connectionIdService = connectionIdService;
        this.dsse = dsse;
    }

    @Override
    public final DsseEnvelope sign(SigningContext context, byte[] payload) {
        KmsClient client = cache.get(connectionIdService.id(context), () -> buildClient(context));
        String keyId = context.get(SlsaParams.KMS_KEY_ID);
        SigningAlgorithmSpec algorithm = SigningAlgorithmSpec.fromValue(context.get(SlsaParams.SIGNING_ALGORITHM));

        byte[] pae = dsse.pae(DsseEnvelope.IN_TOTO_PAYLOAD_TYPE, payload);
        byte[] digest = digest(algorithm, pae);

        SignResponse response = IOGuard.allowNetworkCall(() -> client.sign(SignRequest.builder()
                .keyId(keyId)
                .message(SdkBytes.fromByteArray(digest))
                .messageType(MessageType.DIGEST)
                .signingAlgorithm(algorithm)
                .build()));

        return dsse.envelope(payload, response.keyId(), response.signature().asByteArray());
    }

    protected abstract SignerClient buildClient(SigningContext context);

    protected KmsClient client(String region, SdkHttpClient httpClient, AwsCredentialsProvider provider) {
        KmsClientBuilder builder = KmsClient.builder()
                .httpClient(httpClient)
                .credentialsProvider(provider);
        if (region != null) {
            builder.region(Region.of(region));
        }
        return builder.build();
    }

    private byte[] digest(SigningAlgorithmSpec spec, byte[] pae) {
        String name = spec.toString();
        String alg;
        if (name.endsWith("384")) {
            alg = "SHA-384";
        } else if (name.endsWith("512")) {
            alg = "SHA-512";
        } else {
            alg = "SHA-256";
        }
        try {
            return MessageDigest.getInstance(alg).digest(pae);
        } catch (NoSuchAlgorithmException e) {
            throw new SigningException(alg + " not available", e);
        }
    }
}
