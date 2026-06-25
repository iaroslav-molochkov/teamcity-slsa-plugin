package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.credentials.keys;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.client.KmsClientCache;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.dsse.DsseService;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.AbstractKmsSigningHandler;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.ConnectionIdService;
import jetbrains.buildServer.serverSide.crypt.EncryptUtil;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;

import java.util.List;

/** KMS signing with a base identity from an explicit access key id + secret (the secret is unscrambled here). */
@Component
public class StaticKmsSigningHandler extends AbstractKmsSigningHandler {

    public StaticKmsSigningHandler(KmsClientCache cache, ConnectionIdService connectionIdService, DsseService dsse) {
        super(cache, connectionIdService, dsse);
    }

    @Override
    public SignerType type() {
        return SignerType.AWS_KMS_STATIC;
    }

    @Override
    protected AwsCredentialsProvider baseProvider(SigningContext context, SdkHttpClient httpClient,
                                                  List<AutoCloseable> closeables) {
        AwsBasicCredentials credentials = AwsBasicCredentials.create(
                context.get(SlsaParams.ACCESS_KEY_ID), tryUnscramble(context.get(SlsaParams.SECRET_ACCESS_KEY)));
        return StaticCredentialsProvider.create(credentials);
    }

    private String tryUnscramble(String value) {
        return EncryptUtil.isScrambled(value) ? EncryptUtil.unscramble(value) : value;
    }
}
