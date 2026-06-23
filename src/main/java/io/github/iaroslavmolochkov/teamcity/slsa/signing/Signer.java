package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import org.jetbrains.annotations.NotNull;

/**
 * A signing operation bound to a single validated config — produced by a {@link SignerFactory} and
 * used once per build. It signs the provenance payload and returns the DSSE envelope; the config and
 * any backend resources (KMS client, local key) are captured by the factory that created it.
 */
@FunctionalInterface
public interface Signer {

    @NotNull
    DsseEnvelope sign(@NotNull byte[] payload);
}
