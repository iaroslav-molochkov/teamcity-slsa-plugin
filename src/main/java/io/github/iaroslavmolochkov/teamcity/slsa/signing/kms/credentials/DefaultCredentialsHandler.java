package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.credentials;

import io.github.iaroslavmolochkov.teamcity.slsa.signing.CredentialsType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;

import java.util.List;

/** A base identity from the AWS default provider chain (env, profile, container/instance role). */
@Component
public class DefaultCredentialsHandler implements AwsCredentialsHandler {

    @Override
    public CredentialsType type() {
        return CredentialsType.DEFAULT_CREDENTIALS;
    }

    @Override
    public AwsCredentialsProvider create(SigningContext context, SdkHttpClient httpClient,
                                         List<AutoCloseable> closeables) {
        DefaultCredentialsProvider provider = DefaultCredentialsProvider.builder().build();
        closeables.add(provider);
        return provider;
    }
}
