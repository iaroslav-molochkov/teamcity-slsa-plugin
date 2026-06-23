package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import jetbrains.buildServer.serverSide.InvalidProperty;
import org.jetbrains.annotations.NotNull;

import java.util.List;
import java.util.Map;

/**
 * Validates a signer's raw build-feature params — the anti-corruption boundary, used identically by
 * the UI parameters processor and the runtime. Returns the validation errors (empty when valid);
 * it never builds a config (that's the {@link ConfigMapper}). Selected by {@link #signerId()}.
 */
public interface Validator {

    @NotNull
    String signerId();

    @NotNull
    List<InvalidProperty> validate(@NotNull Map<String, String> params);
}
