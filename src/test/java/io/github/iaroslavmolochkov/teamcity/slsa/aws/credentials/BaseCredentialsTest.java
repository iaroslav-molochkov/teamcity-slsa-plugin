package io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.KmsSignerConfig;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BaseCredentialsTest {

    private final BaseCredentialsRegistry registry =
            new BaseCredentialsRegistry(List.of(new DefaultCredentials(), new StaticCredentials()));

    private static KmsSignerConfig config(CredentialsSource source, AwsKeys keys) {
        return new KmsSignerConfig("us-east-1", "k", SigningAlgorithmSpec.ECDSA_SHA_256,
                source, keys, CredentialsMode.DIRECT, null, null);
    }

    @Test
    void defaultCreatesProviderChain() {
        AwsCredentialsProvider provider = registry.create(config(CredentialsSource.DEFAULT, null));
        assertInstanceOf(DefaultCredentialsProvider.class, provider);
        assertTrue(registry.validate(CredentialsSource.DEFAULT, Map.of()).isEmpty());
    }

    @Test
    void staticRequiresKeysThenCreates() {
        assertFalse(registry.validate(CredentialsSource.STATIC, Map.of()).isEmpty());

        AwsCredentialsProvider provider = registry.create(config(CredentialsSource.STATIC, new AwsKeys("AKIA", "secret")));
        assertInstanceOf(StaticCredentialsProvider.class, provider);
        assertEquals("AKIA", provider.resolveCredentials().accessKeyId());
    }

    @Test
    void staticExtractsKeysFromParams() {
        AwsKeys keys = registry.keys(CredentialsSource.STATIC, Map.of(
                SlsaParams.ACCESS_KEY_ID, "AKIA", SlsaParams.SECRET_ACCESS_KEY, "secret"));
        assertEquals("AKIA", keys.accessKeyId());
        assertEquals("secret", keys.secret());
    }

    @Test
    void sourceFromValueIsCaseInsensitiveAndRejectsUnknown() {
        assertEquals(CredentialsSource.STATIC, CredentialsSource.fromValue("STATIC"));
        assertNull(CredentialsSource.fromValue("nope"));
    }
}
