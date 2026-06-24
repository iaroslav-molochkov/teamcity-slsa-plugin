package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;

import java.util.UUID;

/** Produces the stable client-cache id for one connection type. */
public interface ConnectionKeyHandler {

    SignerType type();

    UUID id(SigningContext context);
}
