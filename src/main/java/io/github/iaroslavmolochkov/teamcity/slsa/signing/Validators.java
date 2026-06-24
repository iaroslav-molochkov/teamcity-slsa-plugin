package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.springframework.stereotype.Component;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Runs the {@link Validator} matching the context's signer type (looked up in a map, no branching).
 * Backs both the UI parameters processor and the build-time pre-check. Selecting an absent or unknown
 * signer is itself a validation error.
 */
@Component
public class Validators {

    private final Map<SignerType, Validator> validators = new EnumMap<>(SignerType.class);

    public Validators(List<Validator> validators) {
        for (Validator validator : validators) {
            this.validators.put(validator.type(), validator);
        }
    }

    public List<InvalidProperty> validate(SigningContext context) {
        Validator validator = validators.get(context.type());
        return validator == null ? selectionError(context) : validator.validate(context);
    }

    private List<InvalidProperty> selectionError(SigningContext context) {
        String raw = context.get(SlsaParams.SIGNER);
        return List.of(new InvalidProperty(SlsaParams.SIGNER,
                raw == null ? "A signer must be selected" : "Unknown signer: " + raw));
    }
}
