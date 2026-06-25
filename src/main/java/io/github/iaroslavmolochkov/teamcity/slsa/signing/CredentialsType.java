package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;

import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/** How an AWS KMS signer authenticates to AWS. Held in {@link SlsaParams#CREDENTIALS}, orthogonal to {@link SignerType}. */
public enum CredentialsType {

    DEFAULT_CREDENTIALS(SlsaParams.CREDENTIALS_DEFAULT),
    STATIC_CREDENTIALS(SlsaParams.CREDENTIALS_STATIC);

    private final String value;

    CredentialsType(String value) {
        this.value = value;
    }

    private static final Map<String, CredentialsType> BY_VALUE = Stream.of(values())
            .collect(Collectors.toUnmodifiableMap(c -> c.value.toLowerCase(Locale.ROOT), Function.identity()));

    public String value() {
        return value;
    }

    public static CredentialsType fromValue(String value) {
        return value == null ? null : BY_VALUE.get(value.toLowerCase(Locale.ROOT));
    }
}
