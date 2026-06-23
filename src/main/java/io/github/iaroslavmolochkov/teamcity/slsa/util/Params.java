package io.github.iaroslavmolochkov.teamcity.slsa.util;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Map;

/** Small helpers for reading build-feature parameters: trim-to-null and lenient int parsing. */
public final class Params {

    private Params() {
    }

    /** The trimmed value for {@code key}, or {@code null} if absent or blank. */
    @Nullable
    public static String get(@NotNull Map<String, String> params, @NotNull String key) {
        return trimToNull(params.get(key));
    }

    /** Returns the trimmed string, or {@code null} if it is {@code null} or blank. */
    @Nullable
    public static String trimToNull(@Nullable String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    /** Parses an integer, or returns {@code null} if the value is {@code null} or not a number. */
    @Nullable
    public static Integer toIntOrNull(@Nullable String value) {
        if (value == null) {
            return null;
        }
        try {
            return Integer.valueOf(value);
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
