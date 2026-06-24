package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.dcp;

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
import software.amazon.awssdk.services.kms.KmsClient;

import java.util.List;

/** Builds a KMS client over the AWS default provider chain (env, profile, container/instance role). */
@Component
public class DefaultKmsClientLoader extends AbstractKmsClientLoader {

    public DefaultKmsClientLoader(KmsClientCache cache, ConnectionIdService connectionIdService) {
        super(cache, connectionIdService);
    }

    @Override
    public SignerType type() {
        return SignerType.AWS_KMS_DEFAULT;
    }

    @Override
    protected SignerClient build(SigningContext context) {
        SdkHttpClient httpClient = UrlConnectionHttpClient.create();
        KmsClient kms = client(context.get(SlsaParams.REGION), httpClient, DefaultCredentialsProvider.builder().build());
        return new SignerClient(kms, List.of(httpClient));
    }
}
