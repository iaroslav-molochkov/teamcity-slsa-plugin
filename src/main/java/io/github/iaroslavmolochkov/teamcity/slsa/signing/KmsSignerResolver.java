package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.KmsSignerConfig;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.client.KmsClientCache;
import jetbrains.buildServer.serverSide.IOGuard;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;

/**
 * The AWS KMS signer, end-to-end: validates via {@link KmsValidator}, maps via {@link KmsConfigMapper},
 * and assembles a {@link Signer} backed by a cached {@link KmsClient}. The private key never leaves
 * KMS (a SLSA L3 property): signing sends only a digest using {@link MessageType#DIGEST}, sidestepping
 * the 4 KiB RAW limit. The actual KMS I/O happens lazily inside {@link Signer#sign}.
 */
@Component
public class KmsSignerResolver implements SignerResolver {

    private final KmsValidator validator;
    private final KmsConfigMapper mapper;
    private final KmsClientCache clientCache;

    public KmsSignerResolver(@NotNull KmsValidator validator,
                             @NotNull KmsConfigMapper mapper,
                             @NotNull KmsClientCache clientCache) {
        this.validator = validator;
        this.mapper = mapper;
        this.clientCache = clientCache;
    }

    @NotNull
    @Override
    public SignerType type() {
        return SignerType.AWS_KMS;
    }

    @NotNull
    @Override
    public List<InvalidProperty> validate(@NotNull Map<String, String> params) {
        return validator.validate(params);
    }

    @NotNull
    @Override
    public Result<Signer> resolve(@NotNull Map<String, String> params) {
        List<InvalidProperty> errors = validator.validate(params);
        if (!errors.isEmpty()) {
            return Result.invalid(errors);
        }
        KmsSignerConfig config = mapper.map(params);
        return Result.of(new Signer() {
            @NotNull
            @Override
            public SignerType type() {
                return SignerType.AWS_KMS;
            }

            @NotNull
            @Override
            public DsseEnvelope sign(@NotNull byte[] payload) {
                return KmsSignerResolver.this.sign(payload, config);
            }
        });
    }

    @NotNull
    private DsseEnvelope sign(@NotNull byte[] payload, @NotNull KmsSignerConfig config) {
        KmsClient client = clientCache.get(config);
        SigningAlgorithmSpec spec = config.algorithm();

        byte[] pae = Pae.encode(DsseEnvelope.IN_TOTO_PAYLOAD_TYPE, payload);
        byte[] digest = digest(spec, pae);

        SignResponse response = IOGuard.allowNetworkCall(() -> client.sign(SignRequest.builder()
                .keyId(config.kmsKeyId())
                .message(SdkBytes.fromByteArray(digest))
                .messageType(MessageType.DIGEST)
                .signingAlgorithm(spec)
                .build()));

        return DsseEnvelope.of(payload, response.keyId(), response.signature().asByteArray());
    }

    /** Hashes the PAE with the digest that matches the signing algorithm's suffix (256/384/512). */
    @NotNull
    private static byte[] digest(@NotNull SigningAlgorithmSpec spec, @NotNull byte[] pae) {
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
