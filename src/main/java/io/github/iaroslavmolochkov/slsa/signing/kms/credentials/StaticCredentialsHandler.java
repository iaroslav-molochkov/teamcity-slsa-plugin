package io.github.iaroslavmolochkov.slsa.signing.kms.credentials;

import io.github.iaroslavmolochkov.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.slsa.signing.CredentialsType;
import io.github.iaroslavmolochkov.slsa.signing.SigningContext;
import jetbrains.buildServer.serverSide.crypt.EncryptUtil;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;

import java.util.List;

/** A base identity from an explicit access key id and secret (the secret is unscrambled here). */
@Component
public class StaticCredentialsHandler implements AwsCredentialsHandler {

    @Override
    public CredentialsType type() {
        return CredentialsType.STATIC_CREDENTIALS;
    }

    @Override
    public AwsCredentialsProvider create(SigningContext context, SdkHttpClient httpClient,
                                         List<AutoCloseable> closeables) {
        AwsBasicCredentials credentials = AwsBasicCredentials.create(
                context.get(SlsaParams.ACCESS_KEY_ID), tryUnscramble(context.get(SlsaParams.SECRET_ACCESS_KEY)));
        return StaticCredentialsProvider.create(credentials);
    }

    private String tryUnscramble(String value) {
        return EncryptUtil.isScrambled(value) ? EncryptUtil.unscramble(value) : value;
    }
}
