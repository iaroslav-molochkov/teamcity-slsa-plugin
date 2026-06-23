package io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/** Where the base AWS credentials come from. The {@link #value()} is the wire value used in params. */
public enum CredentialsSource {

    DEFAULT(SlsaParams.BASE_DEFAULT),
    STATIC(SlsaParams.BASE_STATIC);

    private final String value;

    CredentialsSource(@NotNull String value) {
        this.value = value;
    }

    // Built once at class-load (not per lookup); keyed lowercase for case-insensitive matching.
    private static final Map<String, CredentialsSource> BY_VALUE = Stream.of(values())
            .collect(Collectors.toUnmodifiableMap(s -> s.value.toLowerCase(Locale.ROOT), Function.identity()));

    @NotNull
    public String value() {
        return value;
    }

    /** Resolves a param value to its source, or {@code null} if absent/unknown. */
    @Nullable
    public static CredentialsSource fromValue(@Nullable String value) {
        return value == null ? null : BY_VALUE.get(value.toLowerCase(Locale.ROOT));
    }
}
