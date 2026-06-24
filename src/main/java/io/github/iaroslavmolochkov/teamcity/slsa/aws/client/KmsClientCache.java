package io.github.iaroslavmolochkov.teamcity.slsa.aws.client;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.RemovalCause;
import jetbrains.buildServer.serverSide.BuildServerAdapter;
import jetbrains.buildServer.serverSide.BuildServerListener;
import jetbrains.buildServer.serverSide.TeamCityProperties;
import jetbrains.buildServer.util.EventDispatcher;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.services.kms.KmsClient;

import java.time.Duration;
import java.util.UUID;
import java.util.function.Supplier;

/** Caches {@link KmsClient}s by connection key so builds sharing a connection reuse one client. */
@Component
public class KmsClientCache {

    public static final String MAX_CLIENTS_PROPERTY = "teamcity.slsa.maxKmsClients";
    public static final String CLIENT_TTL_MINUTES_PROPERTY = "teamcity.slsa.kmsClientTtlMinutes";

    private final Cache<UUID, SignerClient> clients;

    public KmsClientCache(EventDispatcher<BuildServerListener> eventDispatcher) {
        int maxClients = TeamCityProperties.getInteger(MAX_CLIENTS_PROPERTY, 32);
        long ttlMinutes = TeamCityProperties.getInteger(CLIENT_TTL_MINUTES_PROPERTY, 60);
        clients = Caffeine.newBuilder()
                .maximumSize(maxClients)
                .expireAfterAccess(Duration.ofMinutes(ttlMinutes))
                .removalListener((UUID key, SignerClient client, RemovalCause cause) -> {
                    if (client != null) {
                        client.close();
                    }
                })
                .build();

        eventDispatcher.addListener(new BuildServerAdapter() {
            @Override
            public void serverShutdown() {
                clear();
            }
        });
    }

    /**
     * Returns the cached {@link KmsClient} for {@code connectionKey}, building one with {@code factory}
     * on first use. The cache owns the resulting {@link SignerClient}'s lifecycle (closed on eviction
     * or shutdown), so callers must not close it.
     */
    public KmsClient get(UUID connectionKey, Supplier<SignerClient> factory) {
        return clients.get(connectionKey, key -> factory.get()).kms();
    }

    /** Closes and drops all cached clients. */
    public void clear() {
        clients.invalidateAll();
        clients.cleanUp();
    }
}
