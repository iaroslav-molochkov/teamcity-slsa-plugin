package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.springframework.stereotype.Component;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/** Runs the {@link Validator} for the context's signer type; an unknown signer is itself an error. */
@Component
public class ParameterValidator {

    private final Map<SignerType, Validator> validators = new EnumMap<>(SignerType.class);

    public ParameterValidator(List<Validator> validators) {
        for (Validator validator : validators) {
            this.validators.put(validator.type(), validator);
        }
    }

    public List<InvalidProperty> validate(SigningContext context) {
        Validator validator = validators.get(context.signerType());
        return validator == null ? selectionError(context) : validator.validate(context);
    }

    private List<InvalidProperty> selectionError(SigningContext context) {
        String raw = context.get(SlsaParams.SIGNER);
        return List.of(new InvalidProperty(SlsaParams.SIGNER,
                raw == null ? "A signer must be selected" : "Unknown signer: " + raw));
    }
}
