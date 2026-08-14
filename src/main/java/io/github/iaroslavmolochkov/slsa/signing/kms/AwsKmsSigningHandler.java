package io.github.iaroslavmolochkov.slsa.signing.kms;

import io.github.iaroslavmolochkov.slsa.aws.client.KmsClientCache;
import io.github.iaroslavmolochkov.slsa.aws.client.SignerClient;
import io.github.iaroslavmolochkov.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.slsa.signing.CredentialsType;
import io.github.iaroslavmolochkov.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.slsa.signing.SigningContext;
import io.github.iaroslavmolochkov.slsa.signing.SigningException;
import io.github.iaroslavmolochkov.slsa.signing.SigningHandler;
import io.github.iaroslavmolochkov.slsa.signing.dsse.DsseEnvelope;
import io.github.iaroslavmolochkov.slsa.signing.dsse.DsseService;
import io.github.iaroslavmolochkov.slsa.signing.kms.credentials.AwsCredentialsHandler;
import jetbrains.buildServer.serverSide.IOGuard;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.KmsClientBuilder;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.StsClientBuilder;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleCredentialsProvider;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Signs a provenance payload with AWS KMS. The base credentials come from the context's
 * {@link CredentialsType} (default chain or static keys), optionally wrapped in an assumed IAM role.
 */
@Component
public class AwsKmsSigningHandler implements SigningHandler {

    private final KmsClientCache cache;
    private final AwsKmsConnectionKey connectionKey;
    private final DsseService dsse;
    private final Map<CredentialsType, AwsCredentialsHandler> credentialHandlers =
            new EnumMap<>(CredentialsType.class);

    public AwsKmsSigningHandler(KmsClientCache cache,
                                AwsKmsConnectionKey connectionKey,
                                DsseService dsse,
                                List<AwsCredentialsHandler> credentialHandlers) {
        this.cache = cache;
        this.connectionKey = connectionKey;
        this.dsse = dsse;
        for (AwsCredentialsHandler factory : credentialHandlers) {
            this.credentialHandlers.put(factory.type(), factory);
        }
    }

    @Override
    public SignerType type() {
        return SignerType.AWS_KMS;
    }

    @Override
    public DsseEnvelope sign(SigningContext context, byte[] payload) {
        KmsClient client = cache.get(connectionKey.id(context), () -> buildClient(context));
        String keyId = context.get(SlsaParams.KMS_KEY_ID);
        String signingAlgorithm = context.get(SlsaParams.SIGNING_ALGORITHM);
        SigningAlgorithmSpec algorithm = SigningAlgorithmSpec.fromValue(signingAlgorithm);

        if (algorithm == null) {
            throw new SigningException("Unsupported signing algorithm: " + signingAlgorithm);
        }

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

    private SignerClient buildClient(SigningContext context) {
        String region = context.get(SlsaParams.REGION);
        boolean fips = useFipsEndpoints(context);
        SdkHttpClient httpClient = ApacheHttpClient.create();
        List<AutoCloseable> closeables = new ArrayList<>();
        closeables.add(httpClient);
        AwsCredentialsProvider provider = baseProvider(context, httpClient, closeables);

        if (context.assumeRole()) {
            provider = assumeRole(context, region, fips, httpClient, provider, closeables);
        }

        KmsClient kms = client(region, fips, httpClient, provider);
        return new SignerClient(kms, closeables);
    }

    static boolean useFipsEndpoints(SigningContext context) {
        return Boolean.parseBoolean(context.get(SlsaParams.USE_FIPS_ENDPOINTS));
    }

    private AwsCredentialsProvider baseProvider(SigningContext context, SdkHttpClient httpClient,
                                               List<AutoCloseable> closeables) {
        AwsCredentialsHandler factory = credentialHandlers.get(context.credentialsType());

        if (factory == null) {
            throw new SigningException("No credentials provider for: " + context.credentialsType());
        }

        return factory.create(context, httpClient, closeables);
    }

    private AwsCredentialsProvider assumeRole(SigningContext context, String region, boolean fips,
                                             SdkHttpClient httpClient, AwsCredentialsProvider base,
                                             List<AutoCloseable> closeables) {
        StsClientBuilder stsBuilder = StsClient.builder()
                .httpClient(httpClient)
                .credentialsProvider(base);

        if (region != null) {
            stsBuilder.region(Region.of(region));
        }

        if (fips) {
            stsBuilder.fipsEnabled(true);
        }

        StsClient sts = stsBuilder.build();
        closeables.add(sts);
        String sessionName = context.get(SlsaParams.ASSUME_ROLE_SESSION_NAME);

        AssumeRoleRequest.Builder request = AssumeRoleRequest.builder()
                .roleArn(context.get(SlsaParams.ASSUME_ROLE_ARN))
                .roleSessionName(sessionName == null ? SlsaParams.DEFAULT_SESSION_NAME : sessionName);
        String externalId = context.get(SlsaParams.ASSUME_ROLE_EXTERNAL_ID);

        if (externalId != null) {
            request.externalId(externalId);
        }

        Integer duration = context.getInt(SlsaParams.ASSUME_ROLE_DURATION_SECONDS);

        if (duration != null) {
            request.durationSeconds(duration);
        }

        StsAssumeRoleCredentialsProvider provider = StsAssumeRoleCredentialsProvider.builder()
                .stsClient(sts)
                .refreshRequest(request.build())
                .build();
        closeables.add(provider);

        return provider;
    }

    private KmsClient client(String region, boolean fips, SdkHttpClient httpClient, AwsCredentialsProvider provider) {
        KmsClientBuilder builder = KmsClient.builder()
                .httpClient(httpClient)
                .credentialsProvider(provider);

        if (region != null) {
            builder.region(Region.of(region));
        }

        if (fips) {
            builder.fipsEnabled(true);
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
