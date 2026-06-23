package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.KmsSignerConfig;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.AssumeRoleSpec;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.AwsCredentialsType;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.AwsKeys;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.util.Params;
import jetbrains.buildServer.serverSide.crypt.EncryptUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.util.Map;

/**
 * Builds a fully-valid, null-free {@link KmsSignerConfig} from params that {@link KmsValidator} has
 * already accepted. The credential payload is filled in for exactly the chosen type; the static
 * secret is unscrambled here (the one decryption point) so downstream code never sees ciphertext.
 */
@Component
public class KmsConfigMapper {

    @NotNull
    public KmsSignerConfig map(@NotNull Map<String, String> params) {
        String region = Params.get(params, SlsaParams.REGION);
        String keyId = Params.get(params, SlsaParams.KMS_KEY_ID);
        SigningAlgorithmSpec algorithm = SigningAlgorithmSpec.fromValue(Params.get(params, SlsaParams.SIGNING_ALGORITHM));
        AwsCredentialsType credentialsType = AwsCredentialsType.fromValue(Params.get(params, SlsaParams.CREDENTIALS));

        AwsKeys keys = null;
        AssumeRoleSpec assumeRole = null;
        String stsEndpoint = null;
        switch (credentialsType) {
            case STATIC -> keys = new AwsKeys(
                    Params.get(params, SlsaParams.ACCESS_KEY_ID),
                    reveal(Params.get(params, SlsaParams.SECRET_ACCESS_KEY)));
            case ASSUME_ROLE -> {
                String sessionName = Params.get(params, SlsaParams.ASSUME_ROLE_SESSION_NAME);
                assumeRole = new AssumeRoleSpec(
                        Params.get(params, SlsaParams.ASSUME_ROLE_ARN),
                        sessionName == null ? SlsaParams.DEFAULT_SESSION_NAME : sessionName,
                        Params.get(params, SlsaParams.ASSUME_ROLE_EXTERNAL_ID),
                        Params.toIntOrNull(Params.get(params, SlsaParams.ASSUME_ROLE_DURATION_SECONDS)));
                stsEndpoint = Params.get(params, SlsaParams.STS_ENDPOINT);
            }
            case DEFAULT -> { /* no extra config */ }
        }

        return new KmsSignerConfig(region, keyId, algorithm, credentialsType, keys, assumeRole, stsEndpoint);
    }

    /** Unscrambles a TeamCity-stored secret; plain values pass through. */
    @Nullable
    private static String reveal(@Nullable String value) {
        if (value == null) {
            return null;
        }
        return EncryptUtil.isScrambled(value) ? EncryptUtil.unscramble(value) : value;
    }
}
