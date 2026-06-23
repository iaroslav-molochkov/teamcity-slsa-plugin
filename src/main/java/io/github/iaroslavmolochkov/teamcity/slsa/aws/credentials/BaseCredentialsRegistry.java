package io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.KmsSignerConfig;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/** Resolves the {@link BaseCredentials} source by its {@link CredentialsSource} type. */
@Component
public class BaseCredentialsRegistry {

    private final Map<CredentialsSource, BaseCredentials> sources = new EnumMap<>(CredentialsSource.class);

    public BaseCredentialsRegistry(@NotNull List<BaseCredentials> sources) {
        for (BaseCredentials source : sources) {
            this.sources.put(source.type(), source);
        }
    }

    /** Validates the params for the given source. */
    @NotNull
    public List<InvalidProperty> validate(@NotNull CredentialsSource source, @NotNull Map<String, String> params) {
        return sources.get(source).validate(params);
    }

    /** Extracts the typed keys (if any) for the given source during mapping. */
    @Nullable
    public AwsKeys keys(@NotNull CredentialsSource source, @NotNull Map<String, String> params) {
        return sources.get(source).keys(params);
    }

    /** Builds the provider for the config's source. The source was validated at the boundary. */
    @NotNull
    public AwsCredentialsProvider create(@NotNull KmsSignerConfig config) {
        return sources.get(config.source()).create(config);
    }
}
