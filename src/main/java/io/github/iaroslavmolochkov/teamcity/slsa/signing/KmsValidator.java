package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.BaseCredentialsRegistry;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.CredentialsMode;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.CredentialsResolutions;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.CredentialsSource;
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
 * Validates the AWS KMS signer's params: region, key, and algorithm, plus the two credential axes
 * (base source + resolution mode) delegated to their registries. Mirrors the split the credential
 * beans already use — validation here, mapping in {@link KmsConfigMapper}.
 */
@Component
public class KmsValidator implements Validator {

    private final BaseCredentialsRegistry baseCredentials;
    private final CredentialsResolutions resolutions;

    public KmsValidator(@NotNull BaseCredentialsRegistry baseCredentials,
                        @NotNull CredentialsResolutions resolutions) {
        this.baseCredentials = baseCredentials;
        this.resolutions = resolutions;
    }

    @NotNull
    @Override
    public String signerId() {
        return SlsaParams.SIGNER_AWS_KMS;
    }

    @NotNull
    @Override
    public List<InvalidProperty> validate(@NotNull Map<String, String> params) {
        List<InvalidProperty> errors = new ArrayList<>();

        if (Params.get(params, SlsaParams.REGION) == null) {
            errors.add(new InvalidProperty(SlsaParams.REGION, "AWS region is required"));
        }
        if (Params.get(params, SlsaParams.KMS_KEY_ID) == null) {
            errors.add(new InvalidProperty(SlsaParams.KMS_KEY_ID, "KMS key id / ARN is required"));
        }
        validateAlgorithm(Params.get(params, SlsaParams.SIGNING_ALGORITHM), errors);

        String sourceValue = SlsaParams.baseId(params);
        if (sourceValue == null) {
            errors.add(new InvalidProperty(SlsaParams.CREDENTIALS_SOURCE, "Credentials source is required"));
        } else {
            CredentialsSource source = CredentialsSource.fromValue(sourceValue);
            if (source == null) {
                errors.add(new InvalidProperty(SlsaParams.CREDENTIALS_SOURCE, "Unknown credentials source: " + sourceValue));
            } else {
                errors.addAll(baseCredentials.validate(source, params));
            }
        }

        String modeValue = SlsaParams.mode(params);
        if (modeValue == null) {
            errors.add(new InvalidProperty(SlsaParams.CREDENTIALS_MODE, "Credentials mode is required"));
        } else {
            CredentialsMode mode = CredentialsMode.fromValue(modeValue);
            if (mode == null) {
                errors.add(new InvalidProperty(SlsaParams.CREDENTIALS_MODE, "Unknown credentials mode: " + modeValue));
            } else {
                errors.addAll(resolutions.validate(mode, params));
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
