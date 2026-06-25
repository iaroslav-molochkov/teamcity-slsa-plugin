package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;

import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/** The signing backend. Held in {@link SlsaParams#SIGNER}; for AWS KMS the credentials are a separate axis. */
public enum SignerType {

    SERVER(SlsaParams.SIGNER_SERVER),
    AWS_KMS(SlsaParams.SIGNER_AWS_KMS);

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
