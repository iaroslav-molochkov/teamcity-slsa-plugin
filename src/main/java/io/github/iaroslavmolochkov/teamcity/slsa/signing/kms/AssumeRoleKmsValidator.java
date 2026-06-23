package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.Validator;
import io.github.iaroslavmolochkov.teamcity.slsa.util.Params;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Validates the assume-role KMS signer: region, key, algorithm, the role ARN, and any duration. */
@Component
public class AssumeRoleKmsValidator implements Validator {

    @NotNull
    @Override
    public SignerType type() {
        return SignerType.AWS_KMS_ASSUME_ROLE;
    }

    @NotNull
    @Override
    public List<InvalidProperty> validate(@NotNull Map<String, String> params) {
        List<InvalidProperty> errors = new ArrayList<>();
        Kms.requireRegion(params, errors);
        Kms.requireKeyAndAlgorithm(params, errors);
        if (Params.get(params, SlsaParams.ASSUME_ROLE_ARN) == null) {
            errors.add(new InvalidProperty(SlsaParams.ASSUME_ROLE_ARN, "Role ARN is required to assume a role"));
        }
        String duration = Params.get(params, SlsaParams.ASSUME_ROLE_DURATION_SECONDS);
        if (duration != null && Params.toIntOrNull(duration) == null) {
            errors.add(new InvalidProperty(SlsaParams.ASSUME_ROLE_DURATION_SECONDS,
                    "Session duration must be a whole number of seconds"));
        }
        return errors;
    }
}
