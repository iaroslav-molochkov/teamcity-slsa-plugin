package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import jetbrains.buildServer.serverSide.InvalidProperty;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.List;

/**
 * The outcome of parsing raw build-feature params into a typed signer config: either a valid config
 * or the validation errors. "Parse, don't validate" — a present {@link #config()} is guaranteed valid.
 */
public record ConfigResult<C>(@Nullable C config, @NotNull List<InvalidProperty> errors) {

    @NotNull
    public static <C> ConfigResult<C> of(@NotNull C config) {
        return new ConfigResult<>(config, List.of());
    }

    @NotNull
    public static <C> ConfigResult<C> invalid(@NotNull List<InvalidProperty> errors) {
        return new ConfigResult<>(null, errors);
    }

    public boolean isValid() {
        return errors.isEmpty();
    }
}
