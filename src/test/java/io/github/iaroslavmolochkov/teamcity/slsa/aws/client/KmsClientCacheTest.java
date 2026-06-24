package io.github.iaroslavmolochkov.teamcity.slsa.aws.client;

import jetbrains.buildServer.util.EventDispatcher;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.kms.KmsClient;

import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class KmsClientCacheTest {

    @SuppressWarnings("unchecked")
    private KmsClientCache newCache() {
        return new KmsClientCache(mock(EventDispatcher.class));
    }

    @SuppressWarnings("unchecked")
    private static Supplier<SignerClient> clientFactory() {
        Supplier<SignerClient> factory = mock(Supplier.class);
        when(factory.get()).thenAnswer(inv -> new SignerClient(mock(KmsClient.class), List.of()));
        return factory;
    }

    @Test
    void buildsOncePerConnectionKey() {
        KmsClientCache cache = newCache();
        Supplier<SignerClient> factory = clientFactory();

        UUID connectionKey = UUID.randomUUID();
        KmsClient a = cache.get(connectionKey, factory);
        KmsClient b = cache.get(connectionKey, factory);

        assertSame(a, b);
        verify(factory, times(1)).get();
    }

    @Test
    void buildsDistinctClientPerConnectionKey() {
        KmsClientCache cache = newCache();

        KmsClient a = cache.get(UUID.randomUUID(), clientFactory());
        KmsClient b = cache.get(UUID.randomUUID(), clientFactory());

        assertNotSame(a, b);
    }
}
