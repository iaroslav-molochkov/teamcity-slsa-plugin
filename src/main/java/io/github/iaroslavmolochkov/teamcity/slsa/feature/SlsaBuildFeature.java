package io.github.iaroslavmolochkov.teamcity.slsa.feature;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerHandler;
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
    private final SignerHandler signerHandler;

    public SlsaBuildFeature(@NotNull PluginDescriptor descriptor, @NotNull SignerHandler signerHandler) {
        editUrl = descriptor.getPluginResourcesPath("editSlsaProvenanceFeature.jsp");
        this.signerHandler = signerHandler;
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
    //todo truly?
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
        String signer = Params.get(params, SlsaParams.SIGNER);

        if (signer == null) {
            return "No signer selected";
        }

        if (SlsaParams.SIGNER_SERVER.equals(signer)) {
            return "Sign artifacts with the server's local key";
        }

        String keyId = Params.get(params, SlsaParams.KMS_KEY_ID);
        StringBuilder sb = new StringBuilder("Sign artifacts with KMS key ").append(keyId == null ? "(not set)" : keyId);
        String region = Params.get(params, SlsaParams.REGION);

        if (region != null) {
            sb.append(" in ").append(region);
        }

        String credentials = Params.get(params, SlsaParams.CREDENTIALS);
        sb.append(", ").append(credentials == null ? "(unset)" : credentials).append(" credentials");
        return sb.toString();
    }

    @Nullable
    @Override
    public PropertiesProcessor getParametersProcessor(@NotNull BuildTypeIdentity buildTypeIdentity) {
        return signerHandler::validate;
    }
}
