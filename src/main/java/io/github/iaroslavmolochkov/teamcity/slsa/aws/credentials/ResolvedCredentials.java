package io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials;

import org.jetbrains.annotations.NotNull;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;

import java.util.List;

/**
 * A credentials provider plus the resources that must be closed with it (e.g. the STS client an
 * assume-role provider refreshes through). Direct resolution returns an empty closeables list.
 */
public record ResolvedCredentials(@NotNull AwsCredentialsProvider provider, @NotNull List<AutoCloseable> closeables) {

    @NotNull
    public static ResolvedCredentials of(@NotNull AwsCredentialsProvider provider) {
        return new ResolvedCredentials(provider, List.of());
    }
}
