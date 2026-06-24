package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.client.KmsClientCache;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.client.SignerClient;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.util.Params;
import jetbrains.buildServer.serverSide.crypt.EncryptUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.services.kms.KmsClient;

import java.util.List;
import java.util.Map;

/** Builds a KMS client from an explicit access key id + secret (the secret is unscrambled here). */
@Component
public class StaticKmsClientLoader implements KmsClientLoader {

    private final KmsClientCache cache;

    public StaticKmsClientLoader(@NotNull KmsClientCache cache) {
        this.cache = cache;
    }

    @NotNull
    @Override
    public SignerType type() {
        return SignerType.AWS_KMS_STATIC;
    }

    @NotNull
    @Override
    public KmsClient load(@NotNull Map<String, String> params) {
        StaticKmsConfig config = new StaticKmsConfig(
                Params.get(params, SlsaParams.REGION),
                Params.get(params, SlsaParams.ACCESS_KEY_ID),
                reveal(Params.get(params, SlsaParams.SECRET_ACCESS_KEY)));
        String connectionKey = Kms.connectionKey("static", config.region(), config.accessKeyId(), config.secret());
        return cache.get(connectionKey, () -> build(config));
    }

    @NotNull
    private static SignerClient build(@NotNull StaticKmsConfig config) {
        SdkHttpClient httpClient = UrlConnectionHttpClient.create();
        KmsClient kms = Kms.client(config.region(), httpClient,
                StaticCredentialsProvider.create(AwsBasicCredentials.create(config.accessKeyId(), config.secret())));
        return new SignerClient(kms, List.of(httpClient));
    }

    /** Unscrambles a TeamCity-stored secret; plain values pass through. */
    @NotNull
    private static String reveal(@Nullable String value) {
        return EncryptUtil.isScrambled(value) ? EncryptUtil.unscramble(value) : value;
    }
}
