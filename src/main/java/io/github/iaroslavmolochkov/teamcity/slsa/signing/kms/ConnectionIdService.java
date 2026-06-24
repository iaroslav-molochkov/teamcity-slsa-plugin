package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningException;
import org.springframework.stereotype.Component;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Derives a connection's stable client-cache id by dispatching to its {@link ConnectionKeyHandler}. */
@Component
public class ConnectionIdService {

    private final Map<SignerType, ConnectionKeyHandler> connectionKeyHandlers = new EnumMap<>(SignerType.class);

    public ConnectionIdService(List<ConnectionKeyHandler> connectionKeyHandlers) {
        for (ConnectionKeyHandler handler : connectionKeyHandlers) {
            this.connectionKeyHandlers.put(handler.type(), handler);
        }
    }

    public UUID id(SigningContext context) {
        ConnectionKeyHandler handler = connectionKeyHandlers.get(context.type());
        if (handler == null) {
            throw new SigningException("No connection-key handler for signer: " + context.type());
        }
        return handler.id(context);
    }
}
