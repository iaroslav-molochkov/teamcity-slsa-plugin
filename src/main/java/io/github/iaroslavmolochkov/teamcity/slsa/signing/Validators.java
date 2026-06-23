package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Validates feature params by dispatching to the selected signer's {@link Validator}. The single
 * validation entry point — used directly by the UI parameters processor and reused by
 * {@link ConfigMappers} at build time, so the rules live in exactly one place.
 */
@Component
public class Validators {

    private final Map<String, Validator> validators = new HashMap<>();

    public Validators(@NotNull List<Validator> validators) {
        for (Validator validator : validators) {
            this.validators.put(validator.signerId(), validator);
        }
    }

    /** Returns the validation errors for the params (empty when valid), including signer selection. */
    @NotNull
    public List<InvalidProperty> validate(@NotNull Map<String, String> params) {
        String signerId = SlsaParams.signerId(params);

        if (signerId == null) {
            return List.of(new InvalidProperty(SlsaParams.SIGNER, "A signer must be selected"));
        }

        Validator validator = validators.get(signerId);

        if (validator == null) {
            return List.of(new InvalidProperty(SlsaParams.SIGNER,
                    "Unknown signer '" + signerId + "' (known: " + validators.keySet() + ")"));
        }

        return validator.validate(params);
    }
}
