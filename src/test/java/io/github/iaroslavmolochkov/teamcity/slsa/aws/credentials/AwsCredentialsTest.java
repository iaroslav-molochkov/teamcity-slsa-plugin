package io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.KmsSignerConfig;
import org.jetbrains.annotations.Nullable;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleCredentialsProvider;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

class AwsCredentialsTest {

    private final AwsCredentialsRegistry registry = new AwsCredentialsRegistry(
            List.of(new DefaultAwsCredentials(), new StaticAwsCredentials(), new AssumeRoleAwsCredentials()));

    private static KmsSignerConfig config(AwsCredentialsType type, @Nullable AwsKeys keys, @Nullable AssumeRoleSpec assumeRole) {
        return new KmsSignerConfig("us-east-1", "k", SigningAlgorithmSpec.ECDSA_SHA_256, type, keys, assumeRole, null);
    }

    @Test
    void defaultValidatesEmptyAndBuildsChain() {
        assertTrue(registry.validate(AwsCredentialsType.DEFAULT, Map.of()).isEmpty());
        AwsCredentialsProvider provider = registry.provider(
                config(AwsCredentialsType.DEFAULT, null, null), Region.US_EAST_1, mock(SdkHttpClient.class)).provider();
        assertInstanceOf(DefaultCredentialsProvider.class, provider);
    }

    @Test
    void staticRequiresKeysThenBuilds() {
        assertFalse(registry.validate(AwsCredentialsType.STATIC, Map.of()).isEmpty());

        AwsCredentialsProvider provider = registry.provider(
                config(AwsCredentialsType.STATIC, new AwsKeys("AKIA", "secret"), null),
                Region.US_EAST_1, mock(SdkHttpClient.class)).provider();
        assertInstanceOf(StaticCredentialsProvider.class, provider);
        assertEquals("AKIA", provider.resolveCredentials().accessKeyId());
    }

    @Test
    void assumeRoleRequiresArn() {
        assertFalse(registry.validate(AwsCredentialsType.ASSUME_ROLE, Map.of()).isEmpty());
    }

    @Test
    void assumeRoleBuildsProviderAndCloseables() {
        AssumeRoleSpec spec = new AssumeRoleSpec("arn:aws:iam::1:role/r", "session", null, null);
        ResolvedCredentials resolved = registry.provider(
                config(AwsCredentialsType.ASSUME_ROLE, null, spec), Region.US_EAST_1, mock(SdkHttpClient.class));
        assertInstanceOf(StsAssumeRoleCredentialsProvider.class, resolved.provider());
        assertFalse(resolved.closeables().isEmpty()); // STS client + provider must be closed
    }

    @Test
    void typeFromValueIsCaseInsensitiveAndRejectsUnknown() {
        assertEquals(AwsCredentialsType.ASSUME_ROLE, AwsCredentialsType.fromValue("Assume-Role"));
        assertNull(AwsCredentialsType.fromValue("nope"));
    }
}
