package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The KMS signing algorithms this plugin supports: the SHA-2 pre-hash families (ECDSA and RSA).
 *
 * <p>{@code AwsKmsSigningHandler} pre-hashes the PAE and signs it with {@code MessageType.DIGEST}, which
 * KMS accepts only for these families. The newer KMS specs — {@code SM2_DSA} (SM3 + Z-value),
 * {@code ML_DSA_SHAKE_256} (post-quantum), and the {@code ED25519*} variants (EdDSA signs the raw message,
 * and KMS caps a raw message at 4096 bytes) — do not fit a precomputed SHA-2 digest and are not verifiable
 * with stock {@code cosign}, so they are deliberately excluded.
 */
public final class KmsSigningAlgorithms {

    public static final List<SigningAlgorithmSpec> SUPPORTED = List.of(
            SigningAlgorithmSpec.ECDSA_SHA_256,
            SigningAlgorithmSpec.ECDSA_SHA_384,
            SigningAlgorithmSpec.ECDSA_SHA_512,
            SigningAlgorithmSpec.RSASSA_PSS_SHA_256,
            SigningAlgorithmSpec.RSASSA_PSS_SHA_384,
            SigningAlgorithmSpec.RSASSA_PSS_SHA_512,
            SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256,
            SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_384,
            SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_512);

    private static final Set<String> SUPPORTED_VALUES = SUPPORTED.stream()
            .map(SigningAlgorithmSpec::toString)
            .collect(Collectors.toUnmodifiableSet());

    public static List<String> values() {
        return SUPPORTED.stream().map(SigningAlgorithmSpec::toString).toList();
    }

    public static boolean isSupported(String value) {
        return value != null && SUPPORTED_VALUES.contains(value);
    }

    private KmsSigningAlgorithms() {
    }
}
