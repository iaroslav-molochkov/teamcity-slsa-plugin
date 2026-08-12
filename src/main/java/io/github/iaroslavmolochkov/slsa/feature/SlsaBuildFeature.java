package io.github.iaroslavmolochkov.slsa.feature;

import io.github.iaroslavmolochkov.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.slsa.signing.CredentialsType;
import io.github.iaroslavmolochkov.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.slsa.signing.ParameterValidator;
import io.github.iaroslavmolochkov.slsa.signing.SigningContext;
import jetbrains.buildServer.serverSide.BuildFeature;
import jetbrains.buildServer.serverSide.BuildTypeIdentity;
import jetbrains.buildServer.serverSide.PropertiesProcessor;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;

/** The {@code slsa.provenance} build feature: generates and signs SLSA provenance for finished builds. */
@Component
public class SlsaBuildFeature extends BuildFeature {

    private static final Set<String> SERVER_PARAMS = Set.of(SlsaParams.SERVER_KEY_NAME);
    private static final Set<String> KMS_PARAMS = Set.of(
            SlsaParams.REGION, SlsaParams.USE_FIPS_ENDPOINTS, SlsaParams.KMS_KEY_ID,
            SlsaParams.SIGNING_ALGORITHM, SlsaParams.CREDENTIALS);
    private static final Set<String> STATIC_PARAMS = Set.of(
            SlsaParams.ACCESS_KEY_ID, SlsaParams.SECRET_ACCESS_KEY);
    private static final Set<String> ROLE_PARAMS = Set.of(
            SlsaParams.ASSUME_ROLE_ENABLED, SlsaParams.ASSUME_ROLE_ARN, SlsaParams.ASSUME_ROLE_SESSION_NAME,
            SlsaParams.ASSUME_ROLE_EXTERNAL_ID, SlsaParams.ASSUME_ROLE_DURATION_SECONDS);

    private final String editUrl;
    private final ParameterValidator parameterValidator;

    public SlsaBuildFeature(PluginDescriptor descriptor, ParameterValidator parameterValidator) {
        editUrl = descriptor.getPluginResourcesPath(SlsaEditFeatureController.EDIT_PATH);
        this.parameterValidator = parameterValidator;
    }

    @Override
    @SuppressWarnings("NullableProblems")
    public String getType() {
        return SlsaParams.FEATURE_TYPE;
    }

    @Override
    @SuppressWarnings("NullableProblems")
    public String getDisplayName() {
        return "SLSA Provenance";
    }

    @Override
    public String getEditParametersUrl() {
        return editUrl;
    }

    @Override
    public boolean isMultipleFeaturesPerBuildTypeAllowed() {
        return false;
    }

    @Override
    public boolean isRequiresAgent() {
        return false;
    }

    @Override
    @SuppressWarnings("NullableProblems")
    public String describeParameters(Map<String, String> params) {
        SigningContext context = new SigningContext(params);
        SignerType signer = context.signerType();

        if (signer == null) {
            return "No signer selected";
        }

        if (signer == SignerType.SERVER) {
            return "Sign artifacts with the server's local key";
        }

        String keyId = context.get(SlsaParams.KMS_KEY_ID);
        StringBuilder sb = new StringBuilder("Sign artifacts with KMS key ").append(keyId == null ? "(not set)" : keyId);
        String region = context.get(SlsaParams.REGION);

        if (region != null) {
            sb.append(" in ").append(region);
        }

        sb.append(", ").append(credentialsLabel(context)).append(" credentials");

        if (context.assumeRole()) {
            sb.append(", assuming an IAM role");
        }

        return sb.toString();
    }

    private String credentialsLabel(SigningContext context) {
        CredentialsType source = context.credentialsType();
        if (source == CredentialsType.STATIC_CREDENTIALS) {
            return "access key";
        }
        if (source == CredentialsType.DEFAULT_CREDENTIALS) {
            return "default provider chain";
        }
        return "(no method selected)";
    }

    @Override
    @SuppressWarnings("NullableProblems")
    public PropertiesProcessor getParametersProcessor(BuildTypeIdentity buildTypeIdentity) {
        return params -> {
            SigningContext context = new SigningContext(params);
            stripRetainedParameters(params, context);
            return parameterValidator.validate(context);
        };
    }

    private void stripRetainedParameters(Map<String, String> params, SigningContext context) {
        SignerType type = context.signerType();

        if (type == null) {
            return;
        }

        Set<String> keys = params.keySet();

        if (type == SignerType.SERVER) {
            keys.removeAll(KMS_PARAMS);
            keys.removeAll(STATIC_PARAMS);
            keys.removeAll(ROLE_PARAMS);
            return;
        }

        keys.removeAll(SERVER_PARAMS);

        if (context.credentialsType() != CredentialsType.STATIC_CREDENTIALS) {
            keys.removeAll(STATIC_PARAMS);
        }

        if (!context.assumeRole()) {
            keys.removeAll(ROLE_PARAMS);
        }
    }
}
