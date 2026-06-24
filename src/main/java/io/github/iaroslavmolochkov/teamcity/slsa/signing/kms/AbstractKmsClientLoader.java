package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.client.KmsClientCache;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.client.SignerClient;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.KmsClientBuilder;

/**
 * Skeletal {@link KmsClientLoader}: owns the cache lookup (keyed by the connection id) and the shared
 * KMS client build, so each mode only implements {@link #build} for its own credentials.
 */
public abstract class AbstractKmsClientLoader implements KmsClientLoader {

    private final KmsClientCache cache;
    private final ConnectionIdService connectionIdService;

    protected AbstractKmsClientLoader(KmsClientCache cache, ConnectionIdService connectionIdService) {
        this.cache = cache;
        this.connectionIdService = connectionIdService;
    }

    @Override
    public final KmsClient load(SigningContext context) {
        return cache.get(connectionIdService.id(context), () -> build(context));
    }

    /** Builds the (closeable) client for this mode's credentials. Called only on a cache miss. */
    protected abstract SignerClient build(SigningContext context);

    /**
     * Builds a KMS client over the given HTTP client and provider — the shared bit every mode needs. A
     * {@code null} region is left unset so the SDK's default region provider chain resolves it
     * (e.g. from {@code AWS_REGION}).
     */
    protected KmsClient client(String region, SdkHttpClient httpClient, AwsCredentialsProvider provider) {
        KmsClientBuilder builder = KmsClient.builder()
                .httpClient(httpClient)
                .credentialsProvider(provider);
        if (region != null) {
            builder.region(Region.of(region));
        }
        return builder.build();
    }
}
