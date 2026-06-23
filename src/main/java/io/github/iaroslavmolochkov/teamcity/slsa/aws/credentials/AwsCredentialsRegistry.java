package io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.KmsSignerConfig;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.regions.Region;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/** Resolves the {@link AwsCredentials} strategy by its {@link AwsCredentialsType}. */
@Component
public class AwsCredentialsRegistry {

    private final Map<AwsCredentialsType, AwsCredentials> strategies = new EnumMap<>(AwsCredentialsType.class);

    public AwsCredentialsRegistry(@NotNull List<AwsCredentials> strategies) {
        for (AwsCredentials strategy : strategies) {
            this.strategies.put(strategy.type(), strategy);
        }
    }

    /** Validates the params for the given credentials type. */
    @NotNull
    public List<InvalidProperty> validate(@NotNull AwsCredentialsType type, @NotNull Map<String, String> params) {
        return strategies.get(type).validate(params);
    }

    /** Builds the provider for the config's credentials type. The type was validated at the boundary. */
    @NotNull
    public ResolvedCredentials provider(@NotNull KmsSignerConfig config, @NotNull Region region, @NotNull SdkHttpClient httpClient) {
        return strategies.get(config.credentialsType()).provider(config, region, httpClient);
    }
}
