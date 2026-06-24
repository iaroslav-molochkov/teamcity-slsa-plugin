package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.client.KmsClientCache;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.client.SignerClient;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.util.Params;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.StsClientBuilder;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleCredentialsProvider;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;

import java.net.URI;
import java.util.List;
import java.util.Map;

/**
 * Builds a KMS client whose credentials come from assuming an IAM role via STS, with the default chain
 * as the base identity. The STS and KMS clients share one HTTP client; the STS client and the
 * auto-refreshing provider are tracked as closeables so the cache can release them on eviction.
 */
@Component
public class AssumeRoleKmsClientLoader implements KmsClientLoader {

    private final KmsClientCache cache;

    public AssumeRoleKmsClientLoader(@NotNull KmsClientCache cache) {
        this.cache = cache;
    }

    @NotNull
    @Override
    public SignerType type() {
        return SignerType.AWS_KMS_ASSUME_ROLE;
    }

    @NotNull
    @Override
    public KmsClient load(@NotNull Map<String, String> params) {
        String sessionName = Params.get(params, SlsaParams.ASSUME_ROLE_SESSION_NAME);
        AssumeRoleKmsConfig config = new AssumeRoleKmsConfig(
                Params.get(params, SlsaParams.REGION),
                Params.get(params, SlsaParams.ASSUME_ROLE_ARN),
                sessionName == null ? SlsaParams.DEFAULT_SESSION_NAME : sessionName,
                Params.get(params, SlsaParams.ASSUME_ROLE_EXTERNAL_ID),
                Params.toIntOrNull(Params.get(params, SlsaParams.ASSUME_ROLE_DURATION_SECONDS)),
                Params.get(params, SlsaParams.STS_ENDPOINT));
        String connectionKey = Kms.connectionKey("assume-role", config.region(), config.roleArn(),
                config.externalId() == null ? "" : config.externalId(),
                config.stsEndpoint() == null ? "" : config.stsEndpoint());
        return cache.get(connectionKey, () -> build(config));
    }

    @NotNull
    private static SignerClient build(@NotNull AssumeRoleKmsConfig config) {
        Region region = Region.of(config.region());
        SdkHttpClient httpClient = UrlConnectionHttpClient.create();

        StsClientBuilder stsBuilder = StsClient.builder()
                .region(region)
                .httpClient(httpClient)
                .credentialsProvider(DefaultCredentialsProvider.builder().build());
        if (config.stsEndpoint() != null) {
            stsBuilder.endpointOverride(URI.create(config.stsEndpoint()));
        }
        StsClient sts = stsBuilder.build();

        AssumeRoleRequest.Builder request = AssumeRoleRequest.builder()
                .roleArn(config.roleArn())
                .roleSessionName(config.sessionName());
        if (config.externalId() != null) {
            request.externalId(config.externalId());
        }
        if (config.durationSeconds() != null) {
            request.durationSeconds(config.durationSeconds());
        }

        StsAssumeRoleCredentialsProvider provider = StsAssumeRoleCredentialsProvider.builder()
                .stsClient(sts)
                .refreshRequest(request.build())
                .build();

        KmsClient kms = Kms.client(config.region(), httpClient, provider);
        return new SignerClient(kms, List.of(httpClient, sts, provider));
    }
}
