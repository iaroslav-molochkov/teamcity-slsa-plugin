package io.github.iaroslavmolochkov.slsa.signing;

import io.github.iaroslavmolochkov.slsa.config.SlsaParams;

import java.util.Map;

/** One build's feature params, with the {@link SignerType} and assume-role flag resolved once. */
public final class SigningContext {

    private final SignerType type;
    private final CredentialsType credentialsType;
    private final boolean assumeRole;
    private final Map<String, String> params;
    private final boolean includeCustomBuildParameters;
    private final boolean failBuildOnError;

    public SigningContext(Map<String, String> params) {
        this.params = params;
        this.type = SignerType.fromValue(get(SlsaParams.SIGNER));
        this.credentialsType = CredentialsType.fromValue(get(SlsaParams.CREDENTIALS));
        this.assumeRole = Boolean.parseBoolean(get(SlsaParams.ASSUME_ROLE_ENABLED));
        this.includeCustomBuildParameters = Boolean.parseBoolean(get(SlsaParams.INCLUDE_CUSTOM_BUILD_PARAMETERS));
        this.failBuildOnError = Boolean.parseBoolean(get(SlsaParams.FAIL_BUILD_ON_ERROR));
    }

    public SignerType signerType() {
        return type;
    }

    public CredentialsType credentialsType() {
        return credentialsType;
    }

    public boolean assumeRole() {
        return assumeRole;
    }

    public boolean includeCustomBuildParameters() {
        return includeCustomBuildParameters;
    }

    public boolean failBuildOnError() {
        return failBuildOnError;
    }

    public String get(String key) {
        String value = params.get(key);

        if (value == null) {
            return null;
        }

        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    public Integer getInt(String key) {
        String value = get(key);

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
