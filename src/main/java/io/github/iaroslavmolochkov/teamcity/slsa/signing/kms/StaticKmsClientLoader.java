package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.client.KmsClientCache;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.client.SignerClient;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
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
public class StaticKmsClientLoader implements KmsClientLoader {

    private final KmsClientCache cache;
    private final ConnectionIdService connectionIdService;

    public StaticKmsClientLoader(KmsClientCache cache, ConnectionIdService connectionIdService) {
        this.cache = cache;
        this.connectionIdService = connectionIdService;
    }

    @Override
    public SignerType type() {
        return SignerType.AWS_KMS_STATIC;
    }

    @Override
    public KmsClient load(SigningContext context) {
        StaticKmsConfig config = new StaticKmsConfig(
                context.get(SlsaParams.REGION),
                context.get(SlsaParams.ACCESS_KEY_ID),
                reveal(context.get(SlsaParams.SECRET_ACCESS_KEY)));
        return cache.get(connectionIdService.id(context), () -> build(config));
    }

    private static SignerClient build(StaticKmsConfig config) {
        SdkHttpClient httpClient = UrlConnectionHttpClient.create();
        KmsClient kms = Kms.client(config.region(), httpClient,
                StaticCredentialsProvider.create(AwsBasicCredentials.create(config.accessKeyId(), config.secret())));
        return new SignerClient(kms, List.of(httpClient));
    }

    /** Unscrambles a TeamCity-stored secret; plain values pass through. */
    private static String reveal(String value) {
        return EncryptUtil.isScrambled(value) ? EncryptUtil.unscramble(value) : value;
    }
}
