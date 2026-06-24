package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.Validator;
import jetbrains.buildServer.serverSide.InvalidProperty;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.util.List;
import java.util.Map;

/**
 * Skeletal {@link Validator} for the KMS modes: the checks common to every mode — key id + algorithm
 * (always), region (when required) — live here as {@code protected} helpers, so each mode's validator
 * only adds its own fields.
 */
public abstract class AbstractKmsValidator implements Validator {

    protected void requireKeyAndAlgorithm(Map<String, String> params, List<InvalidProperty> errors) {
        if (SigningContext.get(params, SlsaParams.KMS_KEY_ID) == null) {
            errors.add(new InvalidProperty(SlsaParams.KMS_KEY_ID, "KMS key id / ARN is required"));
        }
        String algorithm = SigningContext.get(params, SlsaParams.SIGNING_ALGORITHM);
        if (algorithm == null) {
            errors.add(new InvalidProperty(SlsaParams.SIGNING_ALGORITHM, "Signing algorithm is required"));
        } else if (SigningAlgorithmSpec.fromValue(algorithm) == SigningAlgorithmSpec.UNKNOWN_TO_SDK_VERSION) {
            errors.add(new InvalidProperty(SlsaParams.SIGNING_ALGORITHM, "Unknown signing algorithm: " + algorithm));
        }
    }

    protected void requireRegion(Map<String, String> params, List<InvalidProperty> errors) {
        if (SigningContext.get(params, SlsaParams.REGION) == null) {
            errors.add(new InvalidProperty(SlsaParams.REGION, "AWS region is required"));
        }
    }
}
