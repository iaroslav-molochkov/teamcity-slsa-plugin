package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import org.jetbrains.annotations.NotNull;

/**
 * A signing operation bound to a validated config — produced by a {@link SignerProcessor}. It signs
 * the provenance payload and returns the DSSE envelope; its backend (a cached KMS client, the local
 * key) is held as fields on the concrete signer, so the signing logic lives in one place.
 */
public interface Signer {

    @NotNull
    SignerType type();

    @NotNull
    DsseEnvelope sign(@NotNull byte[] payload);
}
