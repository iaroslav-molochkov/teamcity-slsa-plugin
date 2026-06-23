package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * Connection descriptor for the assume-role KMS client: an STS role-assumption layered over the default
 * chain. Role ARN and session name are always set (the latter defaulted); the rest are optional.
 */
record AssumeRoleKmsConfig(@NotNull String region, @NotNull String roleArn, @NotNull String sessionName,
                           @Nullable String externalId, @Nullable Integer durationSeconds,
                           @Nullable String stsEndpoint) {

    @NotNull
    String connectionKey() {
        return Kms.connectionKey("assume-role", region, roleArn,
                externalId == null ? "" : externalId,
                stsEndpoint == null ? "" : stsEndpoint);
    }
}
