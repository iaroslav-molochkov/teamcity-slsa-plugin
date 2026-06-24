package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import org.jetbrains.annotations.NotNull;
import software.amazon.awssdk.services.kms.KmsClient;

/**
 * Builds (or fetches from cache) the KMS client for one AWS credentials mode. Selected by
 * {@link #type()}; the {@link KmsSigningService} picks the right loader from the context's type. The
 * "construct or get from cache" job lives here — separate from validation and from signing.
 */
public interface KmsClientLoader {

    @NotNull
    SignerType type();

    @NotNull
    KmsClient load(@NotNull SigningContext context);
}
