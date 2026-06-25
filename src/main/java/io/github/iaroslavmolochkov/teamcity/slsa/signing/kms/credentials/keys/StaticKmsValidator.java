package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.credentials.keys;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.AbstractKmsValidator;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/** Validates the static-keys KMS signer: key, algorithm, the access key id + secret, and the assumed role when enabled. */
@Component
public class StaticKmsValidator extends AbstractKmsValidator {

    @Override
    public SignerType type() {
        return SignerType.AWS_KMS_STATIC;
    }

    @Override
    public List<InvalidProperty> validate(SigningContext context) {
        List<InvalidProperty> errors = new ArrayList<>();
        requireKeyAndAlgorithm(context, errors);
        if (context.get(SlsaParams.ACCESS_KEY_ID) == null) {
            errors.add(new InvalidProperty(SlsaParams.ACCESS_KEY_ID, "Access key id is required for static credentials"));
        }
        if (context.get(SlsaParams.SECRET_ACCESS_KEY) == null) {
            errors.add(new InvalidProperty(SlsaParams.SECRET_ACCESS_KEY, "Secret access key is required for static credentials"));
        }
        validateAssumeRole(context, errors);
        return errors;
    }
}
