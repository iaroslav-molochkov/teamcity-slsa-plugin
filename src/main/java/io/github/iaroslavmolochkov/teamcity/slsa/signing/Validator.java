package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import jetbrains.buildServer.serverSide.InvalidProperty;

import java.util.List;

/** Validates one signer type's params; shared by the UI processor and the build-time check. */
public interface Validator {

    SignerType type();

    List<InvalidProperty> validate(SigningContext context);
}
