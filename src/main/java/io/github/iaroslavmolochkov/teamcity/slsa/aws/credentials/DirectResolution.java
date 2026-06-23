package io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.KmsSignerConfig;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.regions.Region;

import java.util.List;
import java.util.Map;

/** Uses the base credentials directly — no role assumption, nothing extra to close. */
@Component
public class DirectResolution implements CredentialsResolution {

    private final BaseCredentialsRegistry baseCredentials;

    public DirectResolution(@NotNull BaseCredentialsRegistry baseCredentials) {
        this.baseCredentials = baseCredentials;
    }

    @NotNull
    @Override
    public CredentialsMode type() {
        return CredentialsMode.DIRECT;
    }

    @NotNull
    @Override
    public List<InvalidProperty> validate(@NotNull Map<String, String> params) {
        return List.of();
    }

    @Nullable
    @Override
    public AssumeRoleSpec assumeRole(@NotNull Map<String, String> params) {
        return null;
    }

    @NotNull
    @Override
    public ResolvedCredentials resolve(@NotNull KmsSignerConfig config, @NotNull Region region, @NotNull SdkHttpClient httpClient) {
        return ResolvedCredentials.of(baseCredentials.create(config));
    }
}
