package io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.KmsSignerConfig;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.regions.Region;

import java.util.List;
import java.util.Map;

/**
 * The AWS default provider chain — env, sys-props, web-identity (EKS/IRSA), SSO, profile, container,
 * instance role. Needs no config, so it's the path for k8s/cloud-hosted servers.
 */
@Component
public class DefaultAwsCredentials implements AwsCredentials {

    @NotNull
    @Override
    public AwsCredentialsType type() {
        return AwsCredentialsType.DEFAULT;
    }

    @NotNull
    @Override
    public List<InvalidProperty> validate(@NotNull Map<String, String> params) {
        return List.of();
    }

    @NotNull
    @Override
    public ResolvedCredentials provider(@NotNull KmsSignerConfig config, @NotNull Region region, @NotNull SdkHttpClient httpClient) {
        return ResolvedCredentials.of(DefaultCredentialsProvider.builder().build());
    }
}
