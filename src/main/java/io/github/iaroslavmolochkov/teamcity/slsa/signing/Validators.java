package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.springframework.stereotype.Component;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Resolves the signer type from the params and runs the matching {@link Validator} (looked up in a map,
 * no branching on type). Backs both the UI parameters processor and the build-time pre-check. Selecting
 * an absent or unknown signer is itself a validation error.
 */
@Component
public class Validators {

    private final Map<SignerType, Validator> validators = new EnumMap<>(SignerType.class);

    public Validators(List<Validator> validators) {
        for (Validator validator : validators) {
            this.validators.put(validator.type(), validator);
        }
    }

    public List<InvalidProperty> validate(Map<String, String> params) {
        Validator validator = validators.get(SignerType.fromValue(SigningContext.get(params, SlsaParams.SIGNER)));
        return validator == null ? selectionError(params) : validator.validate(params);
    }

    private static List<InvalidProperty> selectionError(Map<String, String> params) {
        String raw = SigningContext.get(params, SlsaParams.SIGNER);
        return List.of(new InvalidProperty(SlsaParams.SIGNER,
                raw == null ? "A signer must be selected" : "Unknown signer: " + raw));
    }
}
