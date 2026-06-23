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
import jetbrains.buildServer.serverSide.crypt.EncryptUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.services.kms.KmsClient;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * KMS signer backed by an explicit AWS access key id + secret. The secret is unscrambled here (the one
 * decryption point) so it never reaches the client builder or the cache key as ciphertext.
 */
@Component
public class StaticKmsSignerProcessor implements SignerProcessor {

    private final KmsClientCache clientCache;

    public StaticKmsSignerProcessor(@NotNull KmsClientCache clientCache) {
        this.clientCache = clientCache;
    }

    @NotNull
    @Override
    public SignerType type() {
        return SignerType.AWS_KMS_STATIC;
    }

    @NotNull
    @Override
    public List<InvalidProperty> validate(@NotNull Map<String, String> params) {
        List<InvalidProperty> errors = new ArrayList<>();
        Kms.requireRegion(params, errors);
        Kms.requireKeyAndAlgorithm(params, errors);
        if (Params.get(params, SlsaParams.ACCESS_KEY_ID) == null) {
            errors.add(new InvalidProperty(SlsaParams.ACCESS_KEY_ID, "Access key id is required for static credentials"));
        }
        if (Params.get(params, SlsaParams.SECRET_ACCESS_KEY) == null) {
            errors.add(new InvalidProperty(SlsaParams.SECRET_ACCESS_KEY, "Secret access key is required for static credentials"));
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
        StaticKmsConfig config = new StaticKmsConfig(
                Params.get(params, SlsaParams.REGION),
                Params.get(params, SlsaParams.KMS_KEY_ID),
                Kms.algorithm(params),
                Params.get(params, SlsaParams.ACCESS_KEY_ID),
                reveal(Params.get(params, SlsaParams.SECRET_ACCESS_KEY)));
        return Result.of(new KmsSigner(type(),
                () -> clientCache.get(config.connectionKey(), () -> client(config)),
                config.keyId(), config.algorithm()));
    }

    @NotNull
    private static SignerClient client(@NotNull StaticKmsConfig config) {
        SdkHttpClient httpClient = UrlConnectionHttpClient.create();
        KmsClient kms = Kms.client(config.region(), httpClient,
                StaticCredentialsProvider.create(AwsBasicCredentials.create(config.accessKeyId(), config.secret())));
        return new SignerClient(kms, List.of(httpClient));
    }

    /** Unscrambles a TeamCity-stored secret; plain values pass through. */
    @NotNull
    private static String reveal(@Nullable String value) {
        // validate() guarantees the secret is present before we get here.
        return EncryptUtil.isScrambled(value) ? EncryptUtil.unscramble(value) : value;
    }
}
