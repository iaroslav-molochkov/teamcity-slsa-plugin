package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import io.github.iaroslavmolochkov.teamcity.slsa.signing.DsseEnvelope;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.Pae;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.Signer;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningException;
import jetbrains.buildServer.serverSide.IOGuard;
import org.jetbrains.annotations.NotNull;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.function.Supplier;

/**
 * Signs provenance with AWS KMS, shared by all three KMS modes — they differ only in how the client is
 * built, not in the signing itself. The private key never leaves KMS (a SLSA L3 property): we send only
 * a digest using {@link MessageType#DIGEST}, sidestepping the 4 KiB RAW limit.
 *
 * <p>The client is resolved lazily via {@code clientSupplier} on the first {@link #sign}, so the
 * (potentially network-touching) client build happens on the attestation pool rather than the
 * build-finishing thread.
 */
public final class KmsSigner implements Signer {

    private final SignerType type;
    private final Supplier<KmsClient> clientSupplier;
    private final String keyId;
    private final SigningAlgorithmSpec algorithm;

    public KmsSigner(@NotNull SignerType type, @NotNull Supplier<KmsClient> clientSupplier,
                     @NotNull String keyId, @NotNull SigningAlgorithmSpec algorithm) {
        this.type = type;
        this.clientSupplier = clientSupplier;
        this.keyId = keyId;
        this.algorithm = algorithm;
    }

    @NotNull
    @Override
    public SignerType type() {
        return type;
    }

    @NotNull
    @Override
    public DsseEnvelope sign(@NotNull byte[] payload) {
        KmsClient client = clientSupplier.get();

        byte[] pae = Pae.encode(DsseEnvelope.IN_TOTO_PAYLOAD_TYPE, payload);
        byte[] digest = digest(algorithm, pae);

        SignResponse response = IOGuard.allowNetworkCall(() -> client.sign(SignRequest.builder()
                .keyId(keyId)
                .message(SdkBytes.fromByteArray(digest))
                .messageType(MessageType.DIGEST)
                .signingAlgorithm(algorithm)
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
