package io.github.iaroslavmolochkov.slsa.config;

/** Parameter keys (and their fixed values) for the {@code slsa.provenance} build feature. */
public final class SlsaParams {

    public static final String FEATURE_TYPE = "slsa.provenance";

    public static final String FAIL_BUILD_ON_ERROR = "slsa.failBuildOnError";

    public static final String INCLUDE_CUSTOM_BUILD_PARAMETERS = "slsa.includeCustomBuildParameters";

    public static final String SIGNER = "slsa.signer";
    public static final String SIGNER_SERVER = "server";
    public static final String SIGNER_AWS_KMS = "aws-kms";

    public static final String SERVER_PRIVATE_KEY_PATH = "slsa.server.privateKeyPath";

    public static final String REGION = "slsa.aws.region";
    public static final String KMS_KEY_ID = "slsa.kms.keyId";
    public static final String SIGNING_ALGORITHM = "slsa.kms.signingAlgorithm";

    public static final String CREDENTIALS = "slsa.aws.credentials";
    public static final String CREDENTIALS_DEFAULT = "default-credentials";
    public static final String CREDENTIALS_STATIC = "static-credentials";

    public static final String ACCESS_KEY_ID = "slsa.aws.accessKeyId";
    public static final String SECRET_ACCESS_KEY = "secure:slsa.aws.secretAccessKey";

    public static final String ASSUME_ROLE_ENABLED = "slsa.aws.assumeRole.enabled";
    public static final String ASSUME_ROLE_ARN = "slsa.aws.assumeRole.arn";
    public static final String ASSUME_ROLE_SESSION_NAME = "slsa.aws.assumeRole.sessionName";
    public static final String ASSUME_ROLE_EXTERNAL_ID = "slsa.aws.assumeRole.externalId";
    public static final String ASSUME_ROLE_DURATION_SECONDS = "slsa.aws.assumeRole.durationSeconds";

    public static final String STS_ENDPOINT = "slsa.aws.stsEndpoint";

    public static final String DEFAULT_SESSION_NAME = "teamcity-slsa-signer";

    private SlsaParams() {
    }
}
