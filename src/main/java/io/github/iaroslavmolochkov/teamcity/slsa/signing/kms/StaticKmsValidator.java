package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.Validator;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Validates the static-keys KMS signer: region, key, algorithm, and the access key id + secret. */
@Component
public class StaticKmsValidator implements Validator {

    @NotNull
    @Override
    public SignerType type() {
        return SignerType.AWS_KMS_STATIC;
    }

    @NotNull
    @Override
    public List<InvalidProperty> validate(@NotNull Map<String, String> params) {
        List<InvalidProperty> errors = new ArrayList<>();
        Kms.requireRegion(params, errors);
        Kms.requireKeyAndAlgorithm(params, errors);
        if (SigningContext.get(params, SlsaParams.ACCESS_KEY_ID) == null) {
            errors.add(new InvalidProperty(SlsaParams.ACCESS_KEY_ID, "Access key id is required for static credentials"));
        }
        if (SigningContext.get(params, SlsaParams.SECRET_ACCESS_KEY) == null) {
            errors.add(new InvalidProperty(SlsaParams.SECRET_ACCESS_KEY, "Secret access key is required for static credentials"));
        }
        return errors;
    }
}
