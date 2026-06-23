package io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.KmsSignerConfig;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;

import java.util.List;
import java.util.Map;

/**
 * A base AWS credentials source (e.g. {@code default} chain, {@code static} keys). Selected by
 * {@link #type()}; adding a source (web-identity, SSO, …) is a new {@code @Component}. Assume-role is
 * layered on top by a {@link CredentialsResolution}, not here.
 */
public interface BaseCredentials {

    @NotNull
    CredentialsSource type();

    /** Validates this source's own params (e.g. static requires key + secret). */
    @NotNull
    List<InvalidProperty> validate(@NotNull Map<String, String> params);

    /** Extracts this source's typed contribution to the config during parse, or {@code null}. */
    @Nullable
    AwsKeys keys(@NotNull Map<String, String> params);

    /** Builds the provider from a validated config. */
    @NotNull
    AwsCredentialsProvider create(@NotNull KmsSignerConfig config);
}
