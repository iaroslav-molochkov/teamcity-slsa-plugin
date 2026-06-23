package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SignerConfig;
import org.jetbrains.annotations.NotNull;

/**
 * Creates a {@link Signer} bound to a validated {@link SignerConfig}, owning the backend resources
 * (KMS client cache, local key). Selected by {@link #signerId()} matching the config's, so the
 * implementation narrows the config to its own concrete type.
 */
public interface SignerFactory {

    @NotNull
    String signerId();

    @NotNull
    Signer create(@NotNull SignerConfig config);
}
