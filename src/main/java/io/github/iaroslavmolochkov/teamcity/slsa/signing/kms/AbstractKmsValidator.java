package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.Validator;
import jetbrains.buildServer.serverSide.InvalidProperty;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.util.List;

/** Skeletal {@link Validator} for the KMS modes: shared key, algorithm, and assume-role checks as helpers. */
public abstract class AbstractKmsValidator implements Validator {

    private static final int MIN_DURATION_SECONDS = 900;
    private static final int MAX_DURATION_SECONDS = 43200;

    protected void requireKeyAndAlgorithm(SigningContext context, List<InvalidProperty> errors) {
        if (context.get(SlsaParams.KMS_KEY_ID) == null) {
            errors.add(new InvalidProperty(SlsaParams.KMS_KEY_ID, "KMS key id / ARN is required"));
        }
        String algorithm = context.get(SlsaParams.SIGNING_ALGORITHM);
        if (algorithm == null) {
            errors.add(new InvalidProperty(SlsaParams.SIGNING_ALGORITHM, "Signing algorithm is required"));
        } else if (SigningAlgorithmSpec.fromValue(algorithm) == SigningAlgorithmSpec.UNKNOWN_TO_SDK_VERSION) {
            errors.add(new InvalidProperty(SlsaParams.SIGNING_ALGORITHM, "Unknown signing algorithm: " + algorithm));
        }
    }

    protected void validateAssumeRole(SigningContext context, List<InvalidProperty> errors) {
        if (!context.assumeRole()) {
            return;
        }
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
    }
}
