package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

/**
 * Config for the default-provider-chain KMS signer. The region is optional: when absent it is resolved
 * from the environment (e.g. {@code AWS_REGION}), the same way the credentials themselves are.
 */
record DefaultKmsConfig(@Nullable String region, @NotNull String keyId, @NotNull SigningAlgorithmSpec algorithm) {

    @NotNull
    String connectionKey() {
        return Kms.connectionKey("default", region == null ? "" : region);
    }
}
