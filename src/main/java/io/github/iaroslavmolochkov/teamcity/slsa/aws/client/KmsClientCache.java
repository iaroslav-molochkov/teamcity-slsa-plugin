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
import java.util.function.Supplier;

/**
 * Caches {@link KmsClient}s so builds that share a connection reuse one client (and, through it, the
 * SDK's internal session-credential refresh) instead of rebuilding it — and re-assuming roles — each time.
 *
 * <p><b>Keying:</b> by a caller-supplied connection key — a hash of the connection-relevant fields
 * (region, credentials source/identity, assume-role/STS settings) that each signer processor computes
 * for its own config. Deliberately <em>not</em> by project id (one project may have build configs with
 * different connections, and identical connections across projects should share) and <em>not</em> by the
 * KMS key id (a per-{@code sign()} argument).
 *
 * <p>Backed by Caffeine: bounded by size, expired on idle, and each evicted client is closed (its
 * removal listener releases the HTTP sockets and the assume-role refresh thread).
 */
@Component
public class KmsClientCache {

    public static final String MAX_CLIENTS_PROPERTY = "teamcity.slsa.maxKmsClients";
    public static final String CLIENT_TTL_MINUTES_PROPERTY = "teamcity.slsa.kmsClientTtlMinutes";

    private final Cache<String, SignerClient> clients;

    public KmsClientCache(EventDispatcher<BuildServerListener> eventDispatcher) {
        int maxClients = TeamCityProperties.getInteger(MAX_CLIENTS_PROPERTY, 32);
        long ttlMinutes = TeamCityProperties.getInteger(CLIENT_TTL_MINUTES_PROPERTY, 60);
        clients = Caffeine.newBuilder()
                .maximumSize(maxClients)
                .expireAfterAccess(Duration.ofMinutes(ttlMinutes))
                .removalListener((String key, SignerClient client, RemovalCause cause) -> {
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
    public KmsClient get(String connectionKey, Supplier<SignerClient> factory) {
        return clients.get(connectionKey, key -> factory.get()).kms();
    }

    /** Closes and drops all cached clients. */
    public void clear() {
        clients.invalidateAll();
        clients.cleanUp();
    }
}
