package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;

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

    private SigningContext(SignerType type, Map<String, String> params) {
        this.type = type;
        this.params = params;
    }

    /** Wraps the params, resolving the signer type once. Intended to be called on validated params. */
    public static SigningContext of(Map<String, String> params) {
        return new SigningContext(SignerType.fromValue(get(params, SlsaParams.SIGNER)), params);
    }

    /** The resolved signer type. Non-null when built from validated params (the only intended use). */
    public SignerType type() {
        return type;
    }

    /** The trimmed value for {@code key} from these params, or {@code null} if absent or blank. */
    public String get(String key) {
        return get(params, key);
    }

    /** The trimmed value for {@code key}, or {@code null} if absent or blank. */
    public static String get(Map<String, String> params, String key) {
        return trimToNull(params.get(key));
    }

    /** Parses an integer, or returns {@code null} if the value is {@code null} or not a number. */
    public static Integer toIntOrNull(String value) {
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
    public static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
