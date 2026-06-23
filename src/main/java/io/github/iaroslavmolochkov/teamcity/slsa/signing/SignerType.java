package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * The signing mode — a single flat choice that picks both the backend and (for KMS) the credentials
 * source. The {@link SlsaParams#SIGNER} param holds its {@link #value()}; each value is owned end-to-end
 * by exactly one {@code SignerProcessor} bean, looked up by {@link #fromValue}.
 */
public enum SignerType {

    SERVER(SlsaParams.SIGNER_SERVER),
    AWS_KMS_DEFAULT(SlsaParams.SIGNER_AWS_KMS_DEFAULT),
    AWS_KMS_STATIC(SlsaParams.SIGNER_AWS_KMS_STATIC),
    AWS_KMS_ASSUME_ROLE(SlsaParams.SIGNER_AWS_KMS_ASSUME_ROLE);

    private final String value;

    SignerType(@NotNull String value) {
        this.value = value;
    }

    private static final Map<String, SignerType> BY_VALUE = Stream.of(values())
            .collect(Collectors.toUnmodifiableMap(m -> m.value.toLowerCase(Locale.ROOT), Function.identity()));

    @NotNull
    public String value() {
        return value;
    }

    /**
     * Resolves a param value to its mode, or {@code null} if absent/unknown.
     */
    @Nullable
    public static SignerType fromValue(@Nullable String value) {
        return value == null ? null : BY_VALUE.get(value.toLowerCase(Locale.ROOT));
    }
}
