package io.github.iaroslavmolochkov.teamcity.slsa.feature;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.Validators;
import io.github.iaroslavmolochkov.teamcity.slsa.util.Params;
import jetbrains.buildServer.serverSide.BuildFeature;
import jetbrains.buildServer.serverSide.BuildTypeIdentity;
import jetbrains.buildServer.serverSide.PropertiesProcessor;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
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

    public SlsaBuildFeature(@NotNull PluginDescriptor descriptor, @NotNull Validators validators) {
        editUrl = descriptor.getPluginResourcesPath("editSlsaProvenanceFeature.jsp");
        this.validators = validators;
    }

    @NotNull
    @Override
    public String getType() {
        return SlsaParams.FEATURE_TYPE;
    }

    @NotNull
    @Override
    public String getDisplayName() {
        return "SLSA provenance attestation";
    }

    @Nullable
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

    @NotNull
    @Override
    public String describeParameters(@NotNull Map<String, String> params) {
        String signerId = SlsaParams.signerId(params);
        if (signerId == null) {
            return "No signer selected";
        }
        if (SlsaParams.SIGNER_SERVER.equals(signerId)) {
            return "Sign artifacts with the server's local key";
        }
        String keyId = Params.get(params, SlsaParams.KMS_KEY_ID);
        StringBuilder sb = new StringBuilder("Sign artifacts with KMS key ").append(keyId == null ? "(not set)" : keyId);
        String region = Params.get(params, SlsaParams.REGION);
        if (region != null) {
            sb.append(" in ").append(region);
        }
        if (SlsaParams.MODE_ASSUME_ROLE.equals(SlsaParams.mode(params))) {
            sb.append(", assuming a role");
        } else {
            String base = SlsaParams.baseId(params);
            sb.append(", ").append(base == null ? "(unset)" : base).append(" credentials");
        }
        return sb.toString();
    }

    @Nullable
    @Override
    public PropertiesProcessor getParametersProcessor(@NotNull BuildTypeIdentity buildTypeIdentity) {
        return validators::validate;
    }
}
