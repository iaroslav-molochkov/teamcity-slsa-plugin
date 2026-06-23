package io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.KmsSignerConfig;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;

import java.util.List;
import java.util.Map;

/**
 * The AWS default provider chain — env, sys-props, web-identity (EKS/IRSA), SSO, profile, container,
 * instance role. Needs no config, so it's also the path for k8s/cloud-hosted servers.
 */
@Component
public class DefaultCredentials implements BaseCredentials {

    @NotNull
    @Override
    public CredentialsSource type() {
        return CredentialsSource.DEFAULT;
    }

    @NotNull
    @Override
    public List<InvalidProperty> validate(@NotNull Map<String, String> params) {
        return List.of();
    }

    @Nullable
    @Override
    public AwsKeys keys(@NotNull Map<String, String> params) {
        return null;
    }

    @NotNull
    @Override
    public AwsCredentialsProvider create(@NotNull KmsSignerConfig config) {
        return DefaultCredentialsProvider.builder().build();
    }
}
