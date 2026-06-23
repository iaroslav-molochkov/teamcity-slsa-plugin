package io.github.iaroslavmolochkov.teamcity.slsa.aws.client;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.KmsSignerConfig;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.CredentialsMode;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.CredentialsSource;
import jetbrains.buildServer.serverSide.BuildServerListener;
import jetbrains.buildServer.util.EventDispatcher;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class KmsClientCacheTest {

    @SuppressWarnings("unchecked")
    private KmsClientCache newCache(KmsClientFactory factory) {
        return new KmsClientCache(factory, mock(EventDispatcher.class));
    }

    private static KmsSignerConfig config(String region, String keyId) {
        return new KmsSignerConfig(region, keyId, SigningAlgorithmSpec.ECDSA_SHA_256,
                CredentialsSource.DEFAULT, null, CredentialsMode.DIRECT, null, null);
    }

    @Test
    void sharesClientAcrossSameConnectionIgnoringKeyId() {
        KmsClientFactory factory = mock(KmsClientFactory.class);
        when(factory.create(any())).thenAnswer(inv -> new SignerClient(mock(KmsClient.class), List.of()));
        KmsClientCache cache = newCache(factory);

        KmsClient a = cache.get(config("us-east-1", "key-1"));
        KmsClient b = cache.get(config("us-east-1", "key-2")); // different key id, same connection

        assertSame(a, b);
        verify(factory, times(1)).create(any());
    }

    @Test
    void buildsDistinctClientPerConnection() {
        KmsClientFactory factory = mock(KmsClientFactory.class);
        when(factory.create(any())).thenAnswer(inv -> new SignerClient(mock(KmsClient.class), List.of()));
        KmsClientCache cache = newCache(factory);

        KmsClient us = cache.get(config("us-east-1", "key-1"));
        KmsClient eu = cache.get(config("eu-west-1", "key-1"));

        assertNotSame(us, eu);
        verify(factory, times(2)).create(any());
    }
}
