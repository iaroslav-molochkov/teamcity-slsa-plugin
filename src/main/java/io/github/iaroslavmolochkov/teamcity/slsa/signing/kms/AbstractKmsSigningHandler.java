package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningException;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningHandler;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.dsse.DsseEnvelope;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.dsse.DsseService;
import jetbrains.buildServer.serverSide.IOGuard;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Skeletal {@link SigningHandler} for the KMS modes: all three sign identically (digest then
 * {@code kms:Sign}, so the private key never leaves KMS) and differ only in how the client is built.
 * Each mode's subclass supplies its {@link KmsClientLoader}; {@link #type()} follows that loader's type.
 */
public abstract class AbstractKmsSigningHandler implements SigningHandler {

    private final KmsClientLoader loader;
    private final DsseService dsse;

    protected AbstractKmsSigningHandler(KmsClientLoader loader, DsseService dsse) {
        this.loader = loader;
        this.dsse = dsse;
    }

    @Override
    public final SignerType type() {
        return loader.type();
    }

    @Override
    public final DsseEnvelope sign(SigningContext context, byte[] payload) {
        KmsClient client = loader.load(context);
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

    /** Hashes the PAE with the digest that matches the signing algorithm's suffix (256/384/512). */
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
