package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import jetbrains.buildServer.serverSide.InvalidProperty;
import org.jetbrains.annotations.NotNull;

import java.util.List;
import java.util.Map;

/**
 * Owns one signer type end-to-end: it validates the feature params and resolves them into a ready
 * {@link Signer} (validate → map to its own config → assemble). Selected by {@link #type()}.
 * {@link #validate} is exposed on its own so the UI parameters processor can reuse it without
 * assembling anything.
 */
public interface SignerResolver {

    @NotNull
    SignerType type();

    /** Validation errors for the params (empty when valid). Shared with the UI. */
    @NotNull
    List<InvalidProperty> validate(@NotNull Map<String, String> params);

    /** Validates, maps, and assembles a {@link Signer} — or returns the validation errors. */
    @NotNull
    Result<Signer> resolve(@NotNull Map<String, String> params);
}
