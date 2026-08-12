package io.github.iaroslavmolochkov.slsa.signing.server;

import io.github.iaroslavmolochkov.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.slsa.signing.SigningContext;
import io.github.iaroslavmolochkov.slsa.signing.Validator;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.springframework.stereotype.Component;

import java.util.List;

/** Validates the server signer: the named key must exist in the server key store and parse as a usable PEM key. */
@Component
public class ServerValidator implements Validator {

    private final ServerKeyStore keyStore;
    private final ServerKeyParser keyParser;

    public ServerValidator(ServerKeyStore keyStore, ServerKeyParser keyParser) {
        this.keyStore = keyStore;
        this.keyParser = keyParser;
    }

    @Override
    public SignerType type() {
        return SignerType.SERVER;
    }

    @Override
    public List<InvalidProperty> validate(SigningContext context) {
        String name = context.get(SlsaParams.SERVER_KEY_NAME);

        if (name == null) {
            return List.of(new InvalidProperty(SlsaParams.SERVER_KEY_NAME,
                    "A signing key from the server key store is required"));
        }

        try {
            keyParser.parse(keyStore.read(name));
            return List.of();
        } catch (RuntimeException e) {
            return List.of(new InvalidProperty(SlsaParams.SERVER_KEY_NAME,
                    "Cannot load a usable EC, RSA, or Ed25519 private key: " + e.getMessage()));
        }
    }
}
