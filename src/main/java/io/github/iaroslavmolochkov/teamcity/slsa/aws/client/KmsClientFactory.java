package io.github.iaroslavmolochkov.teamcity.slsa.aws.client;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.KmsSignerConfig;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.AwsCredentialsRegistry;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.ResolvedCredentials;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;

import java.util.ArrayList;
import java.util.List;

/**
 * Builds a {@link KmsClient} (wrapped in a {@link SignerClient}) for a validated {@link KmsSignerConfig}.
 * The KMS and STS clients share one HTTP client; since we build it, the {@link SignerClient} owns it,
 * alongside whatever the chosen {@link AwsCredentialsRegistry credentials strategy} returns as closeables.
 */
@Component
public class KmsClientFactory {

    private final AwsCredentialsRegistry credentials;

    public KmsClientFactory(@NotNull AwsCredentialsRegistry credentials) {
        this.credentials = credentials;
    }

    @NotNull
    public SignerClient create(@NotNull KmsSignerConfig config) {
        Region region = Region.of(config.region());

        SdkHttpClient httpClient = UrlConnectionHttpClient.create();
        List<AutoCloseable> closeables = new ArrayList<>();
        closeables.add(httpClient);

        ResolvedCredentials resolved = credentials.provider(config, region, httpClient);
        closeables.addAll(resolved.closeables());

        KmsClient kms = KmsClient.builder()
                .region(region)
                .httpClient(httpClient)
                .credentialsProvider(resolved.provider())
                .build();

        return new SignerClient(kms, closeables);
    }
}
