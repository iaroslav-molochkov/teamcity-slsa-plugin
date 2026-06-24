package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.KmsClientBuilder;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.util.List;
import java.util.Map;

/**
 * Mechanical bits the three KMS processors share — the KMS key id and signing algorithm are common to
 * all of them, and so is building the client. This is plain reuse, not a strategy layer: each processor
 * still owns its own validation, mapping, and credentials. Region is validated per-processor (optional
 * for the default chain, required otherwise).
 */
final class Kms {

    private Kms() {
    }

    /** Adds errors for the always-required KMS fields (key id and signing algorithm). */
    static void requireKeyAndAlgorithm(@NotNull Map<String, String> params, @NotNull List<InvalidProperty> errors) {
        if (SigningContext.get(params, SlsaParams.KMS_KEY_ID) == null) {
            errors.add(new InvalidProperty(SlsaParams.KMS_KEY_ID, "KMS key id / ARN is required"));
        }
        String algorithm = SigningContext.get(params, SlsaParams.SIGNING_ALGORITHM);
        if (algorithm == null) {
            errors.add(new InvalidProperty(SlsaParams.SIGNING_ALGORITHM, "Signing algorithm is required"));
        } else if (SigningAlgorithmSpec.fromValue(algorithm) == SigningAlgorithmSpec.UNKNOWN_TO_SDK_VERSION) {
            errors.add(new InvalidProperty(SlsaParams.SIGNING_ALGORITHM, "Unknown signing algorithm: " + algorithm));
        }
    }

    /** Adds an error if the region is missing (for the modes that require an explicit region). */
    static void requireRegion(@NotNull Map<String, String> params, @NotNull List<InvalidProperty> errors) {
        if (SigningContext.get(params, SlsaParams.REGION) == null) {
            errors.add(new InvalidProperty(SlsaParams.REGION, "AWS region is required"));
        }
    }

    /**
     * Builds a KMS client over the given HTTP client and provider. A {@code null} region is left unset
     * so the SDK's default region provider chain resolves it (e.g. from {@code AWS_REGION}).
     */
    @NotNull
    static KmsClient client(@Nullable String region, @NotNull SdkHttpClient httpClient, @NotNull AwsCredentialsProvider provider) {
        KmsClientBuilder builder = KmsClient.builder()
                .httpClient(httpClient)
                .credentialsProvider(provider);
        if (region != null) {
            builder.region(Region.of(region));
        }
        return builder.build();
    }
}
