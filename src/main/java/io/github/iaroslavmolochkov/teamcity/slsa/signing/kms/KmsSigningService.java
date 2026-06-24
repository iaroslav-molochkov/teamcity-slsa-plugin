package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.DsseService;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.DsseEnvelope;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningException;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningService;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import jetbrains.buildServer.serverSide.IOGuard;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** AWS KMS signing for all three credential modes; signs a digest so the private key never leaves KMS. */
@Component
public class KmsSigningService implements SigningService {

    private final Map<SignerType, KmsClientLoader> loaders = new EnumMap<>(SignerType.class);
    private final DsseService dsse;

    public KmsSigningService(List<KmsClientLoader> loaders, DsseService dsse) {
        for (KmsClientLoader loader : loaders) {
            this.loaders.put(loader.type(), loader);
        }
        this.dsse = dsse;
    }

    @Override
    public Set<SignerType> types() {
        return loaders.keySet();
    }

    @Override
    public DsseEnvelope sign(SigningContext context, byte[] payload) {
        KmsClient client = loaders.get(context.type()).load(context);
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
