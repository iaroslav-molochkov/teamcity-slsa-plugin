package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.sts;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.AbstractKmsValidator;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/** Validates the assume-role KMS signer: region, key, algorithm, the role ARN, and any duration. */
@Component
public class AssumeRoleKmsValidator extends AbstractKmsValidator {

    private static final int MIN_DURATION_SECONDS = 900;
    private static final int MAX_DURATION_SECONDS = 43200;

    @Override
    public SignerType type() {
        return SignerType.AWS_KMS_ASSUME_ROLE;
    }

    @Override
    public List<InvalidProperty> validate(SigningContext context) {
        List<InvalidProperty> errors = new ArrayList<>();
        requireRegion(context, errors);
        requireKeyAndAlgorithm(context, errors);
        if (context.get(SlsaParams.ASSUME_ROLE_ARN) == null) {
            errors.add(new InvalidProperty(SlsaParams.ASSUME_ROLE_ARN, "Role ARN is required to assume a role"));
        }
        if (context.get(SlsaParams.ASSUME_ROLE_DURATION_SECONDS) != null) {
            Integer seconds = context.getInt(SlsaParams.ASSUME_ROLE_DURATION_SECONDS);
            if (seconds == null || seconds < MIN_DURATION_SECONDS || seconds > MAX_DURATION_SECONDS) {
                errors.add(new InvalidProperty(SlsaParams.ASSUME_ROLE_DURATION_SECONDS,
                        "Session duration must be a whole number between " + MIN_DURATION_SECONDS
                                + " and " + MAX_DURATION_SECONDS + " seconds"));
            }
        }
        return errors;
    }
}
