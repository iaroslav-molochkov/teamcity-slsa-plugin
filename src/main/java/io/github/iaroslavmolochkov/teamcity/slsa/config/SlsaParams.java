package io.github.iaroslavmolochkov.teamcity.slsa.config;

/** Parameter keys (and their fixed values) for the {@code slsa.provenance} build feature. */
public final class SlsaParams {

    public static final String FEATURE_TYPE = "slsa.provenance";

    /**
     * The single discriminator: which signer, and (for KMS) how it gets credentials. Required — the
     * UI/DSL always provides it. Each value maps to exactly one {@code SignerProcessor} bean.
     */
    public static final String SIGNER = "slsa.signer";
    public static final String SIGNER_SERVER = "server";
    public static final String SIGNER_AWS_KMS_DEFAULT = "aws-kms-default";
    public static final String SIGNER_AWS_KMS_STATIC = "aws-kms-static";
    public static final String SIGNER_AWS_KMS_ASSUME_ROLE = "aws-kms-assume-role";

    public static final String REGION = "slsa.aws.region";
    public static final String KMS_KEY_ID = "slsa.kms.keyId";
    /** A {@code SigningAlgorithmSpec} name (e.g. {@code ECDSA_SHA_256}). */
    public static final String SIGNING_ALGORITHM = "slsa.kms.signingAlgorithm";

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
}
