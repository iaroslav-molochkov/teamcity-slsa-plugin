package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.KmsSignerConfig;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.AssumeRoleSpec;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.AwsKeys;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.BaseCredentialsRegistry;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.CredentialsMode;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.CredentialsResolutions;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.CredentialsSource;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SignerConfig;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.util.Params;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.util.Map;

/**
 * Builds a fully-valid, null-free {@link KmsSignerConfig} from params that {@link KmsValidator} has
 * already accepted — so every required value is present and the credential axes resolve cleanly.
 */
@Component
public class KmsConfigMapper implements ConfigMapper {

    private final BaseCredentialsRegistry baseCredentials;
    private final CredentialsResolutions resolutions;

    public KmsConfigMapper(@NotNull BaseCredentialsRegistry baseCredentials,
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
    public SignerConfig map(@NotNull Map<String, String> params) {
        String region = Params.get(params, SlsaParams.REGION);
        String keyId = Params.get(params, SlsaParams.KMS_KEY_ID);
        SigningAlgorithmSpec algorithm = SigningAlgorithmSpec.fromValue(Params.get(params, SlsaParams.SIGNING_ALGORITHM));

        CredentialsSource source = CredentialsSource.fromValue(SlsaParams.baseId(params));
        AwsKeys keys = baseCredentials.keys(source, params);
        CredentialsMode mode = CredentialsMode.fromValue(SlsaParams.mode(params));
        AssumeRoleSpec assumeRole = resolutions.assumeRole(mode, params);
        String stsEndpoint = Params.get(params, SlsaParams.STS_ENDPOINT);

        return new KmsSignerConfig(region, keyId, algorithm, source, keys, mode, assumeRole, stsEndpoint);
    }
}
