package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.client.KmsClientCache;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.client.SignerClient;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.services.kms.KmsClient;

import java.util.List;

/** Builds a KMS client over the AWS default provider chain (env, profile, container/instance role). */
@Component
public class DefaultKmsClientLoader implements KmsClientLoader {

    private final KmsClientCache cache;
    private final ConnectionIdService connectionIdService;

    public DefaultKmsClientLoader(KmsClientCache cache, ConnectionIdService connectionIdService) {
        this.cache = cache;
        this.connectionIdService = connectionIdService;
    }

    @Override
    public SignerType type() {
        return SignerType.AWS_KMS_DEFAULT;
    }

    @Override
    public KmsClient load(SigningContext context) {
        DefaultKmsConfig config = new DefaultKmsConfig(context.get(SlsaParams.REGION));
        return cache.get(connectionIdService.id(context), () -> build(config));
    }

    private static SignerClient build(DefaultKmsConfig config) {
        SdkHttpClient httpClient = UrlConnectionHttpClient.create();
        KmsClient kms = Kms.client(config.region(), httpClient, DefaultCredentialsProvider.builder().build());
        return new SignerClient(kms, List.of(httpClient));
    }
}
