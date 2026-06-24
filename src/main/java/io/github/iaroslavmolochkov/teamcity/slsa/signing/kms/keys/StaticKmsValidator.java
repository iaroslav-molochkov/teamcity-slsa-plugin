package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.keys;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.AbstractKmsValidator;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Validates the static-keys KMS signer: region, key, algorithm, and the access key id + secret. */
@Component
public class StaticKmsValidator extends AbstractKmsValidator {

    @Override
    public SignerType type() {
        return SignerType.AWS_KMS_STATIC;
    }

    @Override
    public List<InvalidProperty> validate(Map<String, String> params) {
        List<InvalidProperty> errors = new ArrayList<>();
        requireRegion(params, errors);
        requireKeyAndAlgorithm(params, errors);
        if (SigningContext.get(params, SlsaParams.ACCESS_KEY_ID) == null) {
            errors.add(new InvalidProperty(SlsaParams.ACCESS_KEY_ID, "Access key id is required for static credentials"));
        }
        if (SigningContext.get(params, SlsaParams.SECRET_ACCESS_KEY) == null) {
            errors.add(new InvalidProperty(SlsaParams.SECRET_ACCESS_KEY, "Secret access key is required for static credentials"));
        }
        return errors;
    }
}
