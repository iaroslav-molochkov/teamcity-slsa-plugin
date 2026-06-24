package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;


/**
 * Connection descriptor for the assume-role KMS client: an STS role-assumption layered over the default
 * chain. Role ARN and session name are always set (the latter defaulted); the rest are optional.
 */
record AssumeRoleKmsConfig(String region, String roleArn, String sessionName,
                           String externalId, Integer durationSeconds,
                           String stsEndpoint) {
}
