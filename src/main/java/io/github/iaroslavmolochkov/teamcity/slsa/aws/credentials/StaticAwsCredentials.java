package io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.KmsSignerConfig;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.util.Params;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.regions.Region;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Explicit access key id + secret. The secret is unscrambled by the mapper before it reaches here. */
@Component
public class StaticAwsCredentials implements AwsCredentials {

    @NotNull
    @Override
    public AwsCredentialsType type() {
        return AwsCredentialsType.STATIC;
    }

    @NotNull
    @Override
    public List<InvalidProperty> validate(@NotNull Map<String, String> params) {
        List<InvalidProperty> errors = new ArrayList<>();
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
    public ResolvedCredentials provider(@NotNull KmsSignerConfig config, @NotNull Region region, @NotNull SdkHttpClient httpClient) {
        // keys are present and the secret already unscrambled: the boundary validated and mapped them.
        AwsKeys keys = config.keys();
        return ResolvedCredentials.of(
                StaticCredentialsProvider.create(AwsBasicCredentials.create(keys.accessKeyId(), keys.secret())));
    }
}
