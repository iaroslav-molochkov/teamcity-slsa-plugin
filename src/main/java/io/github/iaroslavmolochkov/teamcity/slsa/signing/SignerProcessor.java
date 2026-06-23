package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import jetbrains.buildServer.serverSide.InvalidProperty;
import org.jetbrains.annotations.NotNull;

import java.util.List;
import java.util.Map;

/**
 * Owns one {@link SignerType} end-to-end. It validates the feature params for its type and, when they
 * are valid, builds the {@link Signer} (a KMS-backed one for the AWS modes, the local key for the
 * server mode). Selected by {@link #type()}; {@link #validate} is exposed on its own so the UI
 * parameters processor can reuse it without building anything.
 */
public interface SignerProcessor {

    @NotNull
    SignerType type();

    /** Validation errors for this type's params (empty when valid). Shared with the UI. */
    @NotNull
    List<InvalidProperty> validate(@NotNull Map<String, String> params);

    /** Validates and, if valid, builds a {@link Signer}; otherwise returns the validation errors. */
    @NotNull
    Result<Signer> process(@NotNull Map<String, String> params);
}
