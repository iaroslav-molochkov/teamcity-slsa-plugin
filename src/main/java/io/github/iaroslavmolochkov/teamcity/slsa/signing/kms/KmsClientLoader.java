package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import org.jetbrains.annotations.NotNull;
import software.amazon.awssdk.services.kms.KmsClient;

import java.util.Map;

/**
 * Builds (or fetches from cache) the KMS client for one AWS credentials mode. Selected by
 * {@link #type()}; the {@link KmsSigningService} picks the right loader from the param type. The
 * "construct or get from cache" job lives here — separate from validation and from signing.
 */
public interface KmsClientLoader {

    @NotNull
    SignerType type();

    @NotNull
    KmsClient load(@NotNull Map<String, String> params);
}
