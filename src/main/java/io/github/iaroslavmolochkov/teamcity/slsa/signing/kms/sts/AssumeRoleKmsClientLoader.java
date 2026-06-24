package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.sts;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.client.KmsClientCache;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.client.SignerClient;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.AbstractKmsClientLoader;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.ConnectionIdService;
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

/**
 * Builds a KMS client whose credentials come from assuming an IAM role via STS, with the default chain
 * as the base identity. The STS and KMS clients share one HTTP client; the STS client and the
 * auto-refreshing provider are tracked as closeables so the cache can release them on eviction.
 */
@Component
public class AssumeRoleKmsClientLoader extends AbstractKmsClientLoader {

    public AssumeRoleKmsClientLoader(KmsClientCache cache, ConnectionIdService connectionIdService) {
        super(cache, connectionIdService);
    }

    @Override
    public SignerType type() {
        return SignerType.AWS_KMS_ASSUME_ROLE;
    }

    @Override
    protected SignerClient build(SigningContext context) {
        String region = context.get(SlsaParams.REGION);
        SdkHttpClient httpClient = UrlConnectionHttpClient.create();

        StsClientBuilder stsBuilder = StsClient.builder()
                .region(Region.of(region))
                .httpClient(httpClient)
                .credentialsProvider(DefaultCredentialsProvider.builder().build());
        String stsEndpoint = context.get(SlsaParams.STS_ENDPOINT);
        if (stsEndpoint != null) {
            stsBuilder.endpointOverride(URI.create(stsEndpoint));
        }
        StsClient sts = stsBuilder.build();

        String sessionName = context.get(SlsaParams.ASSUME_ROLE_SESSION_NAME);
        AssumeRoleRequest.Builder request = AssumeRoleRequest.builder()
                .roleArn(context.get(SlsaParams.ASSUME_ROLE_ARN))
                .roleSessionName(sessionName == null ? SlsaParams.DEFAULT_SESSION_NAME : sessionName);
        String externalId = context.get(SlsaParams.ASSUME_ROLE_EXTERNAL_ID);
        if (externalId != null) {
            request.externalId(externalId);
        }
        Integer duration = context.getInt(SlsaParams.ASSUME_ROLE_DURATION_SECONDS);
        if (duration != null) {
            request.durationSeconds(duration);
        }

        StsAssumeRoleCredentialsProvider provider = StsAssumeRoleCredentialsProvider.builder()
                .stsClient(sts)
                .refreshRequest(request.build())
                .build();

        KmsClient kms = client(region, httpClient, provider);
        return new SignerClient(kms, List.of(httpClient, sts, provider));
    }
}
