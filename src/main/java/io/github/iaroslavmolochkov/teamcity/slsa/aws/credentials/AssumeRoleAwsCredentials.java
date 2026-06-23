package io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.KmsSignerConfig;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.util.Params;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.StsClientBuilder;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleCredentialsProvider;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Assumes an IAM role via STS, using the default provider chain as the base identity. Builds an STS client,
 * feeds it to an auto-refreshing assume-role provider, and returns both as closeables.
 */
@Component
public class AssumeRoleAwsCredentials implements AwsCredentials {

    @NotNull
    @Override
    public AwsCredentialsType type() {
        return AwsCredentialsType.ASSUME_ROLE;
    }

    @NotNull
    @Override
    public List<InvalidProperty> validate(@NotNull Map<String, String> params) {
        List<InvalidProperty> errors = new ArrayList<>();
        if (Params.get(params, SlsaParams.ASSUME_ROLE_ARN) == null) {
            errors.add(new InvalidProperty(SlsaParams.ASSUME_ROLE_ARN, "Role ARN is required to assume a role"));
        }
        //todo assume role max duration?
        String duration = Params.get(params, SlsaParams.ASSUME_ROLE_DURATION_SECONDS);
        if (duration != null && Params.toIntOrNull(duration) == null) {
            errors.add(new InvalidProperty(SlsaParams.ASSUME_ROLE_DURATION_SECONDS,
                    "Session duration must be a whole number of seconds"));
        }
        return errors;
    }

    @NotNull
    @Override
    public ResolvedCredentials provider(@NotNull KmsSignerConfig config, @NotNull Region region, @NotNull SdkHttpClient httpClient) {
        AssumeRoleSpec spec = config.assumeRole();
        AwsCredentialsProvider base = DefaultCredentialsProvider.builder().build();

        StsClientBuilder stsBuilder = StsClient.builder()
                .region(region)
                .httpClient(httpClient)
                .credentialsProvider(base);
        if (config.stsEndpoint() != null) {
            stsBuilder.endpointOverride(URI.create(config.stsEndpoint()));
        }
        StsClient sts = stsBuilder.build();

        AssumeRoleRequest.Builder request = AssumeRoleRequest.builder()
                .roleArn(spec.roleArn())
                .roleSessionName(spec.sessionName());
        if (spec.externalId() != null) {
            request.externalId(spec.externalId());
        }
        if (spec.durationSeconds() != null) {
            request.durationSeconds(spec.durationSeconds());
        }

        StsAssumeRoleCredentialsProvider provider = StsAssumeRoleCredentialsProvider.builder()
                .stsClient(sts)
                .refreshRequest(request.build())
                .build();
        return new ResolvedCredentials(provider, List.of(sts, provider));
    }
}
