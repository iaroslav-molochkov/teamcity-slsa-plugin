package io.github.iaroslavmolochkov.teamcity.slsa.feature;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.Validators;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import jetbrains.buildServer.serverSide.BuildFeature;
import jetbrains.buildServer.serverSide.BuildTypeIdentity;
import jetbrains.buildServer.serverSide.PropertiesProcessor;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * The {@code slsa.provenance} build feature: enabling it makes the server generate and sign SLSA
 * provenance for a configuration's finished builds, using the selected signer.
 *
 * <p>Registering this server extension also exposes the feature to the TeamCity Kotlin DSL
 * ({@code settings.kts}). It is a server-side feature ({@link #isRequiresAgent()} is {@code false}).
 */
@Component
public class SlsaBuildFeature extends BuildFeature {

    private final String editUrl;
    private final Validators validators;

    public SlsaBuildFeature(PluginDescriptor descriptor, Validators validators) {
        editUrl = descriptor.getPluginResourcesPath("editSlsaProvenanceFeature.jsp");
        this.validators = validators;
    }

    @Override
    public String getType() {
        return SlsaParams.FEATURE_TYPE;
    }

    @Override
    public String getDisplayName() {
        return "SLSA provenance attestation";
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
    public String describeParameters(Map<String, String> params) {
        SigningContext context = new SigningContext(params);
        SignerType signer = context.type();

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
        sb.append(", ").append(credentialsLabel(signer)).append(" credentials");
        return sb.toString();
    }

    private String credentialsLabel(SignerType signer) {
        return switch (signer) {
            case AWS_KMS_STATIC -> "access key";
            case AWS_KMS_ASSUME_ROLE -> "assume-role";
            default -> "default provider chain";
        };
    }

    @Override
    public PropertiesProcessor getParametersProcessor(BuildTypeIdentity buildTypeIdentity) {
        return params -> validators.validate(new SigningContext(params));
    }
}
