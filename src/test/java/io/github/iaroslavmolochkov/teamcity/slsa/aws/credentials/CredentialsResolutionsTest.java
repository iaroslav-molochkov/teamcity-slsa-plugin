package io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.KmsSignerConfig;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

class CredentialsResolutionsTest {

    private final BaseCredentialsRegistry bases =
            new BaseCredentialsRegistry(List.of(new DefaultCredentials(), new StaticCredentials()));
    private final CredentialsResolutions resolutions =
            new CredentialsResolutions(List.of(new DirectResolution(bases), new AssumeRoleResolution(bases)));

    @Test
    void directValidatesEmptyAndReturnsBase() {
        assertTrue(resolutions.validate(CredentialsMode.DIRECT, Map.of()).isEmpty());

        KmsSignerConfig config = new KmsSignerConfig("us-east-1", "k", SigningAlgorithmSpec.ECDSA_SHA_256,
                CredentialsSource.DEFAULT, null, CredentialsMode.DIRECT, null, null);
        ResolvedCredentials resolved = resolutions.resolve(config, Region.US_EAST_1, mock(SdkHttpClient.class));
        assertInstanceOf(DefaultCredentialsProvider.class, resolved.provider());
        assertTrue(resolved.closeables().isEmpty());
    }

    @Test
    void assumeRoleRequiresArn() {
        assertFalse(resolutions.validate(CredentialsMode.ASSUME_ROLE, Map.of()).isEmpty());
    }

    @Test
    void assumeRoleExtractsSpec() {
        AssumeRoleSpec spec = resolutions.assumeRole(CredentialsMode.ASSUME_ROLE, Map.of(
                SlsaParams.ASSUME_ROLE_ARN, "arn:aws:iam::1:role/r",
                SlsaParams.ASSUME_ROLE_DURATION_SECONDS, "900"));
        assertFalse(spec == null);
        assertTrue(spec.durationSeconds() == 900);
    }

    @Test
    void modeFromValueIsCaseInsensitiveAndRejectsUnknown() {
        assertTrue(CredentialsMode.ASSUME_ROLE == CredentialsMode.fromValue("Assume-Role"));
        assertNull(CredentialsMode.fromValue("nope"));
    }
}
