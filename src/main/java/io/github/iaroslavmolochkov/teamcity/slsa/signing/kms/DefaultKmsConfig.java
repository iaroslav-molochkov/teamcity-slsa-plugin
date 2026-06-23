package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * Connection descriptor for the default-provider-chain KMS client. The region is optional: when absent
 * it is resolved from the environment (e.g. {@code AWS_REGION}), the same way the credentials are.
 */
record DefaultKmsConfig(@Nullable String region) {

    @NotNull
    String connectionKey() {
        return Kms.connectionKey("default", region == null ? "" : region);
    }
}
