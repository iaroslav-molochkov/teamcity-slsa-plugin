package io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.KmsSignerConfig;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.jetbrains.annotations.NotNull;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.regions.Region;

import java.util.List;
import java.util.Map;

/**
 * One flat AWS credentials strategy ({@code default} / {@code static} / {@code assume-role}). Each
 * validates its own params and builds the provider from a validated {@link KmsSignerConfig}. Adding a
 * strategy is a new {@code @Component}; selected by {@link #type()}.
 */
public interface AwsCredentials {

    @NotNull
    AwsCredentialsType type();

    /** Validates this strategy's params (e.g. static requires key + secret). */
    @NotNull
    List<InvalidProperty> validate(@NotNull Map<String, String> params);

    /** Builds the provider (and any closeables, e.g. an STS client) from a validated config. */
    @NotNull
    ResolvedCredentials provider(@NotNull KmsSignerConfig config, @NotNull Region region, @NotNull SdkHttpClient httpClient);
}
