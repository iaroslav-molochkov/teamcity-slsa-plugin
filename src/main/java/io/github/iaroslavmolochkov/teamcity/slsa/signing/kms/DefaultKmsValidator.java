package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.Validator;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Validates the default-provider-chain KMS signer. Only the key id and algorithm are required; the
 * region is optional (resolved from the environment, e.g. {@code AWS_REGION}, like the credentials).
 */
@Component
public class DefaultKmsValidator implements Validator {

    @NotNull
    @Override
    public SignerType type() {
        return SignerType.AWS_KMS_DEFAULT;
    }

    @NotNull
    @Override
    public List<InvalidProperty> validate(@NotNull Map<String, String> params) {
        List<InvalidProperty> errors = new ArrayList<>();
        Kms.requireKeyAndAlgorithm(params, errors);
        return errors;
    }
}
