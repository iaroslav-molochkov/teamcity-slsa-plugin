package io.github.iaroslavmolochkov.slsa.signing.kms.credentials;

import io.github.iaroslavmolochkov.slsa.signing.CredentialsType;
import io.github.iaroslavmolochkov.slsa.signing.SigningContext;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;

import java.util.List;

/** Builds the base AWS credentials for one {@link CredentialsType}; {@code AwsKmsSigningHandler} routes by {@link #type()}. */
public interface AwsCredentialsHandler {

    CredentialsType type();

    AwsCredentialsProvider create(SigningContext context, SdkHttpClient httpClient, List<AutoCloseable> closeables);
}
