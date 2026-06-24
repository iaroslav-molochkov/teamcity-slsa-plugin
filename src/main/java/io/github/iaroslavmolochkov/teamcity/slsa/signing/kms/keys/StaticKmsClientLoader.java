package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.keys;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.client.KmsClientCache;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.client.SignerClient;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.AbstractKmsClientLoader;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.ConnectionIdService;
import jetbrains.buildServer.serverSide.crypt.EncryptUtil;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.services.kms.KmsClient;

import java.util.List;

/** Builds a KMS client from an explicit access key id + secret (the secret is unscrambled here). */
@Component
public class StaticKmsClientLoader extends AbstractKmsClientLoader {

    public StaticKmsClientLoader(KmsClientCache cache, ConnectionIdService connectionIdService) {
        super(cache, connectionIdService);
    }

    @Override
    public SignerType type() {
        return SignerType.AWS_KMS_STATIC;
    }

    @Override
    protected SignerClient build(SigningContext context) {
        SdkHttpClient httpClient = UrlConnectionHttpClient.create();
        AwsBasicCredentials credentials = AwsBasicCredentials.create(
                context.get(SlsaParams.ACCESS_KEY_ID), tryUnscramble(context.get(SlsaParams.SECRET_ACCESS_KEY)));
        KmsClient kms = client(context.get(SlsaParams.REGION), httpClient, StaticCredentialsProvider.create(credentials));
        return new SignerClient(kms, List.of(httpClient));
    }

    private String tryUnscramble(String value) {
        return EncryptUtil.isScrambled(value) ? EncryptUtil.unscramble(value) : value;
    }
}
