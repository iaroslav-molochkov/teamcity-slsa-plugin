package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.credentials.dcp;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.client.KmsClientCache;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.dsse.DsseService;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.AbstractKmsSigningHandler;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.ConnectionIdService;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;

import java.util.List;

/** KMS signing with a base identity from the AWS default provider chain (env, profile, container/instance role). */
@Component
public class DefaultKmsSigningHandler extends AbstractKmsSigningHandler {

    public DefaultKmsSigningHandler(KmsClientCache cache, ConnectionIdService connectionIdService, DsseService dsse) {
        super(cache, connectionIdService, dsse);
    }

    @Override
    public SignerType type() {
        return SignerType.AWS_KMS_DEFAULT;
    }

    @Override
    protected AwsCredentialsProvider baseProvider(SigningContext context, SdkHttpClient httpClient,
                                                  List<AutoCloseable> closeables) {
        DefaultCredentialsProvider provider = DefaultCredentialsProvider.builder().build();
        closeables.add(provider);
        return provider;
    }
}
