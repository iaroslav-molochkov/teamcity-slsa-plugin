package io.github.iaroslavmolochkov.slsa.signing;


import io.github.iaroslavmolochkov.slsa.signing.dsse.DsseEnvelope;

/** Signs a built provenance payload; {@link SigningService} routes to it by {@link #type()}. */
public interface SigningHandler {

    SignerType type();

    DsseEnvelope sign(SigningContext context, byte[] payload);
}
