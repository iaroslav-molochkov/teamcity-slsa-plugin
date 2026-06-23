package io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.KmsSignerConfig;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.regions.Region;

import java.util.List;
import java.util.Map;

/**
 * Resolves the base credentials into the final provider, selected explicitly by mode ({@code direct}
 * or {@code assume-role}). The primary credentials strategy — assume-role is a first-class peer of
 * direct, not an afterthought wrap. Each resolution owns its construction (incl. any STS client) and
 * returns it as {@link ResolvedCredentials} closeables.
 */
public interface CredentialsResolution {

    @NotNull
    CredentialsMode type();

    /** Validates this mode's own params (e.g. assume-role requires a role ARN). */
    @NotNull
    List<InvalidProperty> validate(@NotNull Map<String, String> params);

    /** Extracts this mode's typed contribution to the config during parse, or {@code null}. */
    @Nullable
    AssumeRoleSpec assumeRole(@NotNull Map<String, String> params);

    /** Builds the final provider (and any closeables) from a validated config. */
    @NotNull
    ResolvedCredentials resolve(@NotNull KmsSignerConfig config, @NotNull Region region, @NotNull SdkHttpClient httpClient);
}
