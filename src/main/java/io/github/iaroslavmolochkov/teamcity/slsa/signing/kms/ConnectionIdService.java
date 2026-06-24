package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningException;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Derives a connection's stable id (its client-cache key): dispatches by type to the matching
 * {@link ConnectionKeyHandler}, which builds the id itself. Pure dispatch — the hashing lives in the
 * handlers.
 */
@Component
public class ConnectionIdService {

    private final Map<SignerType, ConnectionKeyHandler> connectionKeyHandlers = new EnumMap<>(SignerType.class);

    public ConnectionIdService(@NotNull List<ConnectionKeyHandler> connectionKeyHandlers) {
        for (ConnectionKeyHandler handler : connectionKeyHandlers) {
            this.connectionKeyHandlers.put(handler.type(), handler);
        }
    }

    @NotNull
    public String id(@NotNull SigningContext context) {
        ConnectionKeyHandler handler = connectionKeyHandlers.get(context.type());
        if (handler == null) {
            throw new SigningException("No connection-key handler for signer: " + context.type());
        }
        return handler.id(context);
    }
}
