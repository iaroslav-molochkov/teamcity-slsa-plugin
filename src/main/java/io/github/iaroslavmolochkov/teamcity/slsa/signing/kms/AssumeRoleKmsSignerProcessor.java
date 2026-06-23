package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.client.KmsClientCache;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.client.SignerClient;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.Result;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.Signer;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerProcessor;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.util.Params;
import jetbrains.buildServer.serverSide.InvalidProperty;
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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * KMS signer that assumes an IAM role via STS, using the default provider chain as the base identity.
 * The STS and KMS clients share one HTTP client; the auto-refreshing assume-role provider and the STS
 * client are tracked as closeables so the cache can release them on eviction.
 */
@Component
public class AssumeRoleKmsSignerProcessor implements SignerProcessor {

    private final KmsClientCache clientCache;

    public AssumeRoleKmsSignerProcessor(@NotNull KmsClientCache clientCache) {
        this.clientCache = clientCache;
    }

    @NotNull
    @Override
    public SignerType type() {
        return SignerType.AWS_KMS_ASSUME_ROLE;
    }

    @NotNull
    @Override
    public List<InvalidProperty> validate(@NotNull Map<String, String> params) {
        List<InvalidProperty> errors = new ArrayList<>();
        Kms.requireRegion(params, errors);
        Kms.requireKeyAndAlgorithm(params, errors);
        if (Params.get(params, SlsaParams.ASSUME_ROLE_ARN) == null) {
            errors.add(new InvalidProperty(SlsaParams.ASSUME_ROLE_ARN, "Role ARN is required to assume a role"));
        }
        String duration = Params.get(params, SlsaParams.ASSUME_ROLE_DURATION_SECONDS);
        if (duration != null && Params.toIntOrNull(duration) == null) {
            errors.add(new InvalidProperty(SlsaParams.ASSUME_ROLE_DURATION_SECONDS,
                    "Session duration must be a whole number of seconds"));
        }
        return errors;
    }

    @NotNull
    @Override
    public Result<Signer> process(@NotNull Map<String, String> params) {
        List<InvalidProperty> errors = validate(params);
        if (!errors.isEmpty()) {
            return Result.invalid(errors);
        }
        String sessionName = Params.get(params, SlsaParams.ASSUME_ROLE_SESSION_NAME);
        AssumeRoleKmsConfig config = new AssumeRoleKmsConfig(
                Params.get(params, SlsaParams.REGION),
                Params.get(params, SlsaParams.KMS_KEY_ID),
                Kms.algorithm(params),
                Params.get(params, SlsaParams.ASSUME_ROLE_ARN),
                sessionName == null ? SlsaParams.DEFAULT_SESSION_NAME : sessionName,
                Params.get(params, SlsaParams.ASSUME_ROLE_EXTERNAL_ID),
                Params.toIntOrNull(Params.get(params, SlsaParams.ASSUME_ROLE_DURATION_SECONDS)),
                Params.get(params, SlsaParams.STS_ENDPOINT));
        return Result.of(new KmsSigner(type(),
                () -> clientCache.get(config.connectionKey(), () -> client(config)),
                config.keyId(), config.algorithm()));
    }

    @NotNull
    private static SignerClient client(@NotNull AssumeRoleKmsConfig config) {
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
