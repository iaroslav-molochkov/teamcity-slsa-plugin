package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.Validator;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Validates the assume-role KMS signer: region, key, algorithm, the role ARN, and any duration. */
@Component
public class AssumeRoleKmsValidator implements Validator {

    // AWS STS AssumeRole DurationSeconds limits: 15 minutes to 12 hours.
    private static final int MIN_DURATION_SECONDS = 900;
    private static final int MAX_DURATION_SECONDS = 43200;

    @Override
    public SignerType type() {
        return SignerType.AWS_KMS_ASSUME_ROLE;
    }

    @Override
    public List<InvalidProperty> validate(Map<String, String> params) {
        List<InvalidProperty> errors = new ArrayList<>();
        Kms.requireRegion(params, errors);
        Kms.requireKeyAndAlgorithm(params, errors);
        if (SigningContext.get(params, SlsaParams.ASSUME_ROLE_ARN) == null) {
            errors.add(new InvalidProperty(SlsaParams.ASSUME_ROLE_ARN, "Role ARN is required to assume a role"));
        }
        // Duration is optional (AWS defaults to 1h when unset). When given, it must be within AWS's
        // documented range; the role's own MaxSessionDuration may be lower, but we can't see that here.
        String duration = SigningContext.get(params, SlsaParams.ASSUME_ROLE_DURATION_SECONDS);
        if (duration != null) {
            Integer seconds = SigningContext.toIntOrNull(duration);
            if (seconds == null || seconds < MIN_DURATION_SECONDS || seconds > MAX_DURATION_SECONDS) {
                errors.add(new InvalidProperty(SlsaParams.ASSUME_ROLE_DURATION_SECONDS,
                        "Session duration must be a whole number between " + MIN_DURATION_SECONDS
                                + " and " + MAX_DURATION_SECONDS + " seconds"));
            }
        }
        return errors;
    }
}
