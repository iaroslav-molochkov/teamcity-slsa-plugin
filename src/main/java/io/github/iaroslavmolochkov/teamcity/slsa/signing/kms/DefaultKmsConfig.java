package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;


/**
 * Connection descriptor for the default-provider-chain KMS client. The region is optional: when absent
 * it is resolved from the environment (e.g. {@code AWS_REGION}), the same way the credentials are.
 */
record DefaultKmsConfig(String region) {
}
