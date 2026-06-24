package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;

/**
 * Produces the stable id (client-cache key) for one connection type. Selected by {@link #type()};
 * {@link AbstractConnectionKeyHandler} provides the shared hashing skeleton.
 */
public interface ConnectionKeyHandler {

    SignerType type();

    String id(SigningContext context);
}
