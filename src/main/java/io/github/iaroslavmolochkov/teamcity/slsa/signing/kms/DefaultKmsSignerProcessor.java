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
import software.amazon.awssdk.services.kms.KmsClient;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * KMS signer backed by the AWS default provider chain — env, sys-props, web-identity (EKS/IRSA), SSO,
 * profile, container, instance role. Needs no credentials config, so it's the path for cloud-hosted
 * servers. The region is optional too: if unset it is resolved from the environment.
 */
@Component
public class DefaultKmsSignerProcessor implements SignerProcessor {

    private final KmsClientCache clientCache;

    public DefaultKmsSignerProcessor(@NotNull KmsClientCache clientCache) {
        this.clientCache = clientCache;
    }

    @NotNull
    @Override
    public SignerType type() {
        return SignerType.AWS_KMS_DEFAULT;
    }

    @NotNull
    @Override
    public List<InvalidProperty> validate(@NotNull Map<String, String> params) {
        List<InvalidProperty> errors = new ArrayList<>();
        Kms.requireKeyAndAlgorithm(params, errors);
        return errors;
    }

    @NotNull
    @Override
    public Result<Signer> process(@NotNull Map<String, String> params) {
        List<InvalidProperty> errors = validate(params);
        if (!errors.isEmpty()) {
            return Result.invalid(errors);
        }
        DefaultKmsConfig config = new DefaultKmsConfig(
                Params.get(params, SlsaParams.REGION),
                Params.get(params, SlsaParams.KMS_KEY_ID),
                Kms.algorithm(params));
        return Result.of(new KmsSigner(type(),
                () -> clientCache.get(config.connectionKey(), () -> client(config)),
                config.keyId(), config.algorithm()));
    }

    @NotNull
    private static SignerClient client(@NotNull DefaultKmsConfig config) {
        SdkHttpClient httpClient = UrlConnectionHttpClient.create();
        KmsClient kms = Kms.client(config.region(), httpClient, DefaultCredentialsProvider.builder().build());
        return new SignerClient(kms, List.of(httpClient));
    }
}
