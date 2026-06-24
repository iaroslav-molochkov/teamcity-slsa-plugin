package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import org.jetbrains.annotations.NotNull;

import java.util.Set;

/**
 * Signs an already-built provenance payload. One job: sign. It receives the {@link SigningContext} (to
 * resolve its backend — e.g. the KMS client) and the payload, and returns the DSSE envelope. The
 * {@link #types()} it handles are how {@link SigningServices} routes to it; the AWS modes all share one.
 */
public interface SigningService {

    @NotNull
    Set<SignerType> types();

    @NotNull
    DsseEnvelope sign(@NotNull SigningContext context, @NotNull byte[] payload);
}
