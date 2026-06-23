package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import jetbrains.buildServer.serverSide.InvalidProperty;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.List;

/**
 * The outcome of resolving feature params: either a value or the validation errors. "Parse, don't
 * validate" — a present {@link #value()} is guaranteed valid; {@link #isValid()} is just "no errors".
 */
public record Result<T>(@Nullable T value, @NotNull List<InvalidProperty> errors) {

    @NotNull
    public static <T> Result<T> of(@NotNull T value) {
        return new Result<>(value, List.of());
    }

    @NotNull
    public static <T> Result<T> invalid(@NotNull List<InvalidProperty> errors) {
        return new Result<>(null, errors);
    }

    public boolean isValid() {
        return errors.isEmpty();
    }
}
