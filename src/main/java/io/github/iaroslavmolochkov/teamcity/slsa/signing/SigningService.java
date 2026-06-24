package io.github.iaroslavmolochkov.teamcity.slsa.signing;


import java.util.Set;

/** Signs a built provenance payload; {@link SigningServices} routes to it by {@link #types()}. */
public interface SigningService {

    Set<SignerType> types();

    DsseEnvelope sign(SigningContext context, byte[] payload);
}
