package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import org.jetbrains.annotations.NotNull;

/**
 * A signing operation bound to a validated config — produced by a {@link SignerResolver} and used
 * once per build. It signs the provenance payload and returns the DSSE envelope; the config and any
 * backend resources (KMS client, local key) are captured by the resolver that produced it.
 */
public interface Signer {

    @NotNull
    SignerType type();

    @NotNull
    DsseEnvelope sign(@NotNull byte[] payload);
}
