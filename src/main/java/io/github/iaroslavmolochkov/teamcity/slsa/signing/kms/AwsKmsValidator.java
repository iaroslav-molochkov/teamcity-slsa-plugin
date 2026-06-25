package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.CredentialsType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.Validator;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.util.ArrayList;
import java.util.List;

/** Validates the AWS KMS signer: key, algorithm, credentials method (with static keys when chosen), and any assumed role. */
@Component
public class AwsKmsValidator implements Validator {

    private static final int MIN_DURATION_SECONDS = 900;
    private static final int MAX_DURATION_SECONDS = 43_200;

    @Override
    public SignerType type() {
        return SignerType.AWS_KMS;
    }

    @Override
    public List<InvalidProperty> validate(SigningContext context) {
        List<InvalidProperty> errors = new ArrayList<>();

        requireKeyAndAlgorithm(context, errors);
        validateCredentials(context, errors);
        validateAssumeRole(context, errors);

        return errors;
    }

    private void requireKeyAndAlgorithm(SigningContext context, List<InvalidProperty> errors) {
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

    private void validateCredentials(SigningContext context, List<InvalidProperty> errors) {
        CredentialsType source = context.credentialsType();

        if (source == null) {
            String raw = context.get(SlsaParams.CREDENTIALS);
            errors.add(new InvalidProperty(SlsaParams.CREDENTIALS,
                    raw == null ? "A credentials method must be selected" : "Unknown credentials method: " + raw));

            return;
        }

        if (source == CredentialsType.STATIC_CREDENTIALS) {
            if (context.get(SlsaParams.ACCESS_KEY_ID) == null) {
                errors.add(new InvalidProperty(SlsaParams.ACCESS_KEY_ID, "Access key id is required for static credentials"));
            }

            if (context.get(SlsaParams.SECRET_ACCESS_KEY) == null) {
                errors.add(new InvalidProperty(SlsaParams.SECRET_ACCESS_KEY, "Secret access key is required for static credentials"));
            }
        }
    }

    private void validateAssumeRole(SigningContext context, List<InvalidProperty> errors) {
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
