package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.dcp;

import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.AbstractKmsValidator;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/** Validates the default-provider-chain KMS signer; the region is optional. */
@Component
public class DefaultKmsValidator extends AbstractKmsValidator {

    @Override
    public SignerType type() {
        return SignerType.AWS_KMS_DEFAULT;
    }

    @Override
    public List<InvalidProperty> validate(SigningContext context) {
        List<InvalidProperty> errors = new ArrayList<>();
        requireKeyAndAlgorithm(context, errors);
        return errors;
    }
}
