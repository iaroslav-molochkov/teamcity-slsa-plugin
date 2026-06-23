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
import software.amazon.awssdk.services.kms.KmsClient;

import java.util.List;
import java.util.Map;

/** Builds a KMS client over the AWS default provider chain (env, profile, container/instance role). */
@Component
public class DefaultKmsClientLoader implements KmsClientLoader {

    private final KmsClientCache cache;

    public DefaultKmsClientLoader(@NotNull KmsClientCache cache) {
        this.cache = cache;
    }

    @NotNull
    @Override
    public SignerType type() {
        return SignerType.AWS_KMS_DEFAULT;
    }

    @NotNull
    @Override
    public KmsClient load(@NotNull Map<String, String> params) {
        DefaultKmsConfig config = new DefaultKmsConfig(Params.get(params, SlsaParams.REGION));
        return cache.get(config.connectionKey(), () -> build(config));
    }

    @NotNull
    private static SignerClient build(@NotNull DefaultKmsConfig config) {
        SdkHttpClient httpClient = UrlConnectionHttpClient.create();
        KmsClient kms = Kms.client(config.region(), httpClient, DefaultCredentialsProvider.builder().build());
        return new SignerClient(kms, List.of(httpClient));
    }
}
