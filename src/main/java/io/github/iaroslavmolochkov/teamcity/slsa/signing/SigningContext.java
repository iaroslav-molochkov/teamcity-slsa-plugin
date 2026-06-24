package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Map;

/**
 * The validated feature params for one build, with the {@link SignerType} resolved once. Created right
 * after validation passes and threaded through the rest of the path (sign, connection id), so the type
 * is never re-derived and downstream code reads params through one place. Also the home for the small
 * param-reading helpers (trim-to-null, lenient int) that used to live in a separate util.
 */
public final class SigningContext {

    private final SignerType type;
    private final Map<String, String> params;

    private SigningContext(@Nullable SignerType type, @NotNull Map<String, String> params) {
        this.type = type;
        this.params = params;
    }

    /** Wraps the params, resolving the signer type once. Intended to be called on validated params. */
    @NotNull
    public static SigningContext of(@NotNull Map<String, String> params) {
        return new SigningContext(SignerType.fromValue(get(params, SlsaParams.SIGNER)), params);
    }

    /** The resolved signer type. Non-null when built from validated params (the only intended use). */
    @NotNull
    public SignerType type() {
        return type;
    }

    /** The trimmed value for {@code key} from these params, or {@code null} if absent or blank. */
    @Nullable
    public String get(@NotNull String key) {
        return get(params, key);
    }

    /** The trimmed value for {@code key}, or {@code null} if absent or blank. */
    @Nullable
    public static String get(@NotNull Map<String, String> params, @NotNull String key) {
        return trimToNull(params.get(key));
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

    /** Returns the trimmed string, or {@code null} if it is {@code null} or blank. */
    @Nullable
    public static String trimToNull(@Nullable String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
