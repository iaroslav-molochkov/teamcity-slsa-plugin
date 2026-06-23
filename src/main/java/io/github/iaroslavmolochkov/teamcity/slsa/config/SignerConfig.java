package io.github.iaroslavmolochkov.teamcity.slsa.config;

import org.jetbrains.annotations.NotNull;

/**
 * Marker for a validated, typed signer configuration. Produced by a {@code ConfigMapper} from raw
 * build-feature params and consumed by the matching {@code SignerFactory}; {@link #signerId()} is how
 * the factory is selected, so the two always agree on the concrete type.
 */
public interface SignerConfig {

    /** The signer this config belongs to (one of the {@code SlsaParams.SIGNER_*} ids). */
    @NotNull
    String signerId();
}
