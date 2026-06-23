package io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/** How the base credentials are resolved into the final provider. {@link #value()} is the wire value. */
public enum CredentialsMode {

    DIRECT(SlsaParams.MODE_DIRECT),
    ASSUME_ROLE(SlsaParams.MODE_ASSUME_ROLE);

    private final String value;

    CredentialsMode(@NotNull String value) {
        this.value = value;
    }

    // Built once at class-load (not per lookup); keyed lowercase for case-insensitive matching.
    private static final Map<String, CredentialsMode> BY_VALUE = Stream.of(values())
            .collect(Collectors.toUnmodifiableMap(m -> m.value.toLowerCase(Locale.ROOT), Function.identity()));

    @NotNull
    public String value() {
        return value;
    }

    /** Resolves a param value to its mode, or {@code null} if absent/unknown. */
    @Nullable
    public static CredentialsMode fromValue(@Nullable String value) {
        return value == null ? null : BY_VALUE.get(value.toLowerCase(Locale.ROOT));
    }
}
