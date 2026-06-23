package io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.KmsSignerConfig;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.regions.Region;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/** Resolves the {@link CredentialsResolution} by its {@link CredentialsMode} type. */
@Component
public class CredentialsResolutions {

    private final Map<CredentialsMode, CredentialsResolution> resolutions = new EnumMap<>(CredentialsMode.class);

    public CredentialsResolutions(@NotNull List<CredentialsResolution> resolutions) {
        for (CredentialsResolution resolution : resolutions) {
            this.resolutions.put(resolution.type(), resolution);
        }
    }

    /** Validates the params for the given mode. */
    @NotNull
    public List<InvalidProperty> validate(@NotNull CredentialsMode mode, @NotNull Map<String, String> params) {
        return resolutions.get(mode).validate(params);
    }

    /** Extracts the typed assume-role spec (if any) for the given mode during mapping. */
    @Nullable
    public AssumeRoleSpec assumeRole(@NotNull CredentialsMode mode, @NotNull Map<String, String> params) {
        return resolutions.get(mode).assumeRole(params);
    }

    /** Resolves the final credentials for the config's mode. The mode was validated at the boundary. */
    @NotNull
    public ResolvedCredentials resolve(@NotNull KmsSignerConfig config, @NotNull Region region, @NotNull SdkHttpClient httpClient) {
        return resolutions.get(config.mode()).resolve(config, region, httpClient);
    }
}
