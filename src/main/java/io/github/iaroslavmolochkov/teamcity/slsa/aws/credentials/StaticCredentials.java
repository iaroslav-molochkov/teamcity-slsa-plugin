package io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.KmsSignerConfig;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.util.Params;
import jetbrains.buildServer.serverSide.InvalidProperty;
import jetbrains.buildServer.serverSide.crypt.EncryptUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Explicit access key id + secret. */
@Component
public class StaticCredentials implements BaseCredentials {

    @NotNull
    @Override
    public CredentialsSource type() {
        return CredentialsSource.STATIC;
    }

    @NotNull
    @Override
    public List<InvalidProperty> validate(@NotNull Map<String, String> params) {
        List<InvalidProperty> errors = new ArrayList<>();
        if (Params.get(params, SlsaParams.ACCESS_KEY_ID) == null) {
            errors.add(new InvalidProperty(SlsaParams.ACCESS_KEY_ID, "Access key id is required for static credentials"));
        }
        if (secret(params) == null) {
            errors.add(new InvalidProperty(SlsaParams.SECRET_ACCESS_KEY, "Secret access key is required for static credentials"));
        }
        return errors;
    }

    @Nullable
    @Override
    public AwsKeys keys(@NotNull Map<String, String> params) {
        String accessKeyId = Params.get(params, SlsaParams.ACCESS_KEY_ID);
        String secret = secret(params);
        return (accessKeyId == null || secret == null) ? null : new AwsKeys(accessKeyId, secret);
    }

    @NotNull
    @Override
    public AwsCredentialsProvider create(@NotNull KmsSignerConfig config) {
        // keys are present: the boundary validated the static base before this config was built.
        AwsKeys keys = config.keys();
        return StaticCredentialsProvider.create(AwsBasicCredentials.create(keys.accessKeyId(), keys.secret()));
    }

    @Nullable
    private static String secret(@NotNull Map<String, String> params) {
        String value = Params.get(params, SlsaParams.SECRET_ACCESS_KEY);
        if (value == null) {
            return null;
        }
        return EncryptUtil.isScrambled(value) ? EncryptUtil.unscramble(value) : value;
    }
}
