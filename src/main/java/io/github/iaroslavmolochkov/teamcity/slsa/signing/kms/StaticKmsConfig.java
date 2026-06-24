package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;


/**
 * Connection descriptor for the static-keys KMS client. The secret is already unscrambled by the loader
 * that maps it, so downstream code never sees ciphertext.
 */
record StaticKmsConfig(String region, String accessKeyId, String secret) {
}
