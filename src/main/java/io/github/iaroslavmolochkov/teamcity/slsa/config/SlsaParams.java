package io.github.iaroslavmolochkov.teamcity.slsa.config;

import io.github.iaroslavmolochkov.teamcity.slsa.util.Params;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Map;

/** Parameter keys for the {@code slsa.provenance} build feature, plus selection helpers. */
public final class SlsaParams {

    public static final String FEATURE_TYPE = "slsa.provenance";

    /** Selects the signing strategy (required — the UI/DSL always provides it). */
    public static final String SIGNER = "slsa.signer";
    public static final String SIGNER_SERVER = "server";
    public static final String SIGNER_AWS_KMS = "aws-kms";

    public static final String REGION = "slsa.aws.region";
    public static final String KMS_KEY_ID = "slsa.kms.keyId";
    /** A {@code SigningAlgorithmSpec} name (e.g. {@code ECDSA_SHA_256}). */
    public static final String SIGNING_ALGORITHM = "slsa.kms.signingAlgorithm";

    /** Selects the base credentials provider (required for the KMS signer). */
    public static final String CREDENTIALS_SOURCE = "slsa.aws.credentialsSource";
    public static final String BASE_DEFAULT = "default";
    public static final String BASE_STATIC = "static";

    /** Selects how the base credentials are resolved (required for the KMS signer). */
    public static final String CREDENTIALS_MODE = "slsa.aws.credentials.mode";
    public static final String MODE_DIRECT = "direct";
    public static final String MODE_ASSUME_ROLE = "assume-role";

    public static final String ACCESS_KEY_ID = "slsa.aws.accessKeyId";
    /** {@code secure:} prefix asks TeamCity to store this scrambled. */
    public static final String SECRET_ACCESS_KEY = "secure:slsa.aws.secretAccessKey";

    public static final String ASSUME_ROLE_ARN = "slsa.aws.assumeRole.arn";
    public static final String ASSUME_ROLE_SESSION_NAME = "slsa.aws.assumeRole.sessionName";
    public static final String ASSUME_ROLE_EXTERNAL_ID = "slsa.aws.assumeRole.externalId";
    public static final String ASSUME_ROLE_DURATION_SECONDS = "slsa.aws.assumeRole.durationSeconds";

    public static final String STS_ENDPOINT = "slsa.aws.stsEndpoint";

    public static final String DEFAULT_SESSION_NAME = "teamcity-slsa-signer";

    private SlsaParams() {
    }

    /** The selected signer id, or {@code null} if not specified — never silently defaulted. */
    @Nullable
    public static String signerId(@NotNull Map<String, String> params) {
        return Params.get(params, SIGNER);
    }

    //todo remove specific names, just user params#get then
    /** The selected base credentials id, or {@code null} if not specified. */
    @Nullable
    public static String baseId(@NotNull Map<String, String> params) {
        return Params.get(params, CREDENTIALS_SOURCE);
    }

    /** The selected resolution mode id, or {@code null} if not specified. */
    @Nullable
    public static String mode(@NotNull Map<String, String> params) {
        return Params.get(params, CREDENTIALS_MODE);
    }
}
