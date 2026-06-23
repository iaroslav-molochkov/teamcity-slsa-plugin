package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.KmsSignerConfig;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.client.KmsClientCache;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SignerConfig;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import jetbrains.buildServer.serverSide.IOGuard;
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

/**
 * Creates {@link Signer}s that sign with AWS KMS. The private key never leaves KMS (a SLSA L3
 * property): signing sends only a digest using {@link MessageType#DIGEST}, sidestepping the 4 KiB
 * RAW limit. The KMS client is shared via {@link KmsClientCache}, keyed on the connection.
 */
@Component
public class KmsSignerFactory implements SignerFactory {

    private final KmsClientCache clientCache;

    public KmsSignerFactory(@NotNull KmsClientCache clientCache) {
        this.clientCache = clientCache;
    }

    @NotNull
    @Override
    public String signerId() {
        return SlsaParams.SIGNER_AWS_KMS;
    }

    @NotNull
    @Override
    public Signer create(@NotNull SignerConfig config) {
        if (!(config instanceof KmsSignerConfig kms)) {
            throw new IllegalStateException("KmsSignerFactory received " + config.getClass().getName());
        }
        return payload -> sign(payload, kms);
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
