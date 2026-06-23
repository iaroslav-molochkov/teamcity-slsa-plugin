package io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials;

import org.jetbrains.annotations.Nullable;

/** Parameters for an STS assume-role (role ARN required; the rest optional). */
public record AssumeRoleSpec(String roleArn, String sessionName,
                             @Nullable String externalId, @Nullable Integer durationSeconds) {
}
