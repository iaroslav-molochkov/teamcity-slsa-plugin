package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;

import java.util.Map;

/** One build's feature params, with the {@link SignerType} resolved once. */
public final class SigningContext {

    private final SignerType type;
    private final Map<String, String> params;

    public SigningContext(Map<String, String> params) {
        this.params = params;
        this.type = SignerType.fromValue(get(SlsaParams.SIGNER));
    }

    public SignerType type() {
        return type;
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
