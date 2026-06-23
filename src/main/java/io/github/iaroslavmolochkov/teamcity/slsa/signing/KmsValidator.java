package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.AwsCredentialsRegistry;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.AwsCredentialsType;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.util.Params;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Validates the AWS KMS signer's params: region, key, algorithm, and the credentials choice. The
 * credentials check is delegated to the selected {@code AwsCredentials} strategy via the registry.
 */
@Component
public class KmsValidator {

    private final AwsCredentialsRegistry credentials;

    public KmsValidator(@NotNull AwsCredentialsRegistry credentials) {
        this.credentials = credentials;
    }

    @NotNull
    public List<InvalidProperty> validate(@NotNull Map<String, String> params) {
        List<InvalidProperty> errors = new ArrayList<>();

        if (Params.get(params, SlsaParams.REGION) == null) {
            errors.add(new InvalidProperty(SlsaParams.REGION, "AWS region is required"));
        }
        if (Params.get(params, SlsaParams.KMS_KEY_ID) == null) {
            errors.add(new InvalidProperty(SlsaParams.KMS_KEY_ID, "KMS key id / ARN is required"));
        }
        validateAlgorithm(Params.get(params, SlsaParams.SIGNING_ALGORITHM), errors);

        String credentialsValue = Params.get(params, SlsaParams.CREDENTIALS);
        if (credentialsValue == null) {
            errors.add(new InvalidProperty(SlsaParams.CREDENTIALS, "A credentials type is required"));
        } else {
            AwsCredentialsType type = AwsCredentialsType.fromValue(credentialsValue);
            if (type == null) {
                errors.add(new InvalidProperty(SlsaParams.CREDENTIALS, "Unknown credentials type: " + credentialsValue));
            } else {
                errors.addAll(credentials.validate(type, params));
            }
        }

        return errors;
    }

    private static void validateAlgorithm(String value, @NotNull List<InvalidProperty> errors) {
        if (value == null) {
            errors.add(new InvalidProperty(SlsaParams.SIGNING_ALGORITHM, "Signing algorithm is required"));
            return;
        }
        if (SigningAlgorithmSpec.fromValue(value) == SigningAlgorithmSpec.UNKNOWN_TO_SDK_VERSION) {
            errors.add(new InvalidProperty(SlsaParams.SIGNING_ALGORITHM, "Unknown signing algorithm: " + value));
        }
    }
}
