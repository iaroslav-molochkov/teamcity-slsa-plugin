package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;

import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/** The signing backend and, for KMS, the base credentials source. Held in {@link SlsaParams#SIGNER}. */
public enum SignerType {

    SERVER(SlsaParams.SIGNER_SERVER),
    AWS_KMS_DEFAULT(SlsaParams.SIGNER_AWS_KMS_DEFAULT),
    AWS_KMS_STATIC(SlsaParams.SIGNER_AWS_KMS_STATIC);

    private final String value;

    SignerType(String value) {
        this.value = value;
    }

    private static final Map<String, SignerType> BY_VALUE = Stream.of(values())
            .collect(Collectors.toUnmodifiableMap(m -> m.value.toLowerCase(Locale.ROOT), Function.identity()));

    public String value() {
        return value;
    }

    public static SignerType fromValue(String value) {
        return value == null ? null : BY_VALUE.get(value.toLowerCase(Locale.ROOT));
    }
}
