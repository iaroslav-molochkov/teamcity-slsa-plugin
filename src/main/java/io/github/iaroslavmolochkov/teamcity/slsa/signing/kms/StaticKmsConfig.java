package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import org.jetbrains.annotations.NotNull;

/**
 * Connection descriptor for the static-keys KMS client. The secret is already unscrambled by the loader
 * that maps it, so downstream code never sees ciphertext.
 */
record StaticKmsConfig(@NotNull String region, @NotNull String accessKeyId, @NotNull String secret) {
}
