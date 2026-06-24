package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import jetbrains.buildServer.serverSide.InvalidProperty;

import java.util.List;
import java.util.Map;

/**
 * Validates one signer type's params. Selected by {@link #type()} and looked up in {@link Validators}.
 * Deliberately standalone (no signing): the UI parameters processor and the build-time path both reuse
 * the same bean.
 */
public interface Validator {

    SignerType type();

    /** Validation errors for this type's params (empty when valid). */
    List<InvalidProperty> validate(Map<String, String> params);
}
