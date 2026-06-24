package io.github.iaroslavmolochkov.teamcity.slsa.signing.server;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.Validator;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.util.List;

/** Validates the server signer: the configured path must point to a readable, usable EC or RSA PEM key. */
@Component
public class ServerValidator implements Validator {

    private final ServerKeyParser keyParser;

    public ServerValidator(ServerKeyParser keyParser) {
        this.keyParser = keyParser;
    }

    @Override
    public SignerType type() {
        return SignerType.SERVER;
    }

    @Override
    public List<InvalidProperty> validate(SigningContext context) {
        String path = context.get(SlsaParams.SERVER_PRIVATE_KEY_PATH);
        if (path == null) {
            return List.of(new InvalidProperty(SlsaParams.SERVER_PRIVATE_KEY_PATH,
                    "A path to a PEM private key file on the server is required"));
        }
        try {
            if (!Path.of(path).isAbsolute()) {
                return List.of(new InvalidProperty(SlsaParams.SERVER_PRIVATE_KEY_PATH,
                        "The key file path must be absolute"));
            }
            keyParser.fromPath(path);
            return List.of();
        } catch (RuntimeException e) {
            return List.of(new InvalidProperty(SlsaParams.SERVER_PRIVATE_KEY_PATH,
                    "Cannot read a usable EC or RSA private key from " + path + ": " + e.getMessage()));
        }
    }
}
