package io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * How the KMS signer obtains AWS credentials — a single flat choice. {@code ASSUME_ROLE} layers an
 * STS role-assumption over the default chain; it is a sibling of the others, not a modifier.
 */
public enum AwsCredentialsType {

    DEFAULT(SlsaParams.CREDENTIALS_DEFAULT),
    STATIC(SlsaParams.CREDENTIALS_STATIC),
    ASSUME_ROLE(SlsaParams.CREDENTIALS_ASSUME_ROLE);

    private final String value;

    AwsCredentialsType(@NotNull String value) {
        this.value = value;
    }

    // Built once at class-load (not per lookup); keyed lowercase for case-insensitive matching.
    private static final Map<String, AwsCredentialsType> BY_VALUE = Stream.of(values())
            .collect(Collectors.toUnmodifiableMap(t -> t.value.toLowerCase(Locale.ROOT), Function.identity()));

    @NotNull
    public String value() {
        return value;
    }

    /** Resolves a param value to its type, or {@code null} if absent/unknown. */
    @Nullable
    public static AwsCredentialsType fromValue(@Nullable String value) {
        return value == null ? null : BY_VALUE.get(value.toLowerCase(Locale.ROOT));
    }
}
