package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import org.jetbrains.annotations.NotNull;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

/**
 * Config for the static-keys KMS signer. The secret is already unscrambled by the processor that maps
 * it, so downstream code never sees ciphertext.
 */
record StaticKmsConfig(@NotNull String region, @NotNull String keyId, @NotNull SigningAlgorithmSpec algorithm,
                       @NotNull String accessKeyId, @NotNull String secret) {

    @NotNull
    String connectionKey() {
        return Kms.connectionKey("static", region, accessKeyId, secret);
    }
}
