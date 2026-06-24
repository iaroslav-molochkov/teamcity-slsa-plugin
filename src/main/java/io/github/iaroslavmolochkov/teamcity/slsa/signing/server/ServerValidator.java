package io.github.iaroslavmolochkov.teamcity.slsa.signing.server;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.Validator;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.springframework.stereotype.Component;

import java.util.List;

/** Validates the server signer: the PEM key must be present and parse into a usable EC or RSA key. */
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
        String pem = context.get(SlsaParams.SERVER_PRIVATE_KEY);
        if (pem == null) {
            return List.of(new InvalidProperty(SlsaParams.SERVER_PRIVATE_KEY, "A PEM private key is required"));
        }
        try {
            keyParser.parse(pem);
            return List.of();
        } catch (RuntimeException e) {
            return List.of(new InvalidProperty(SlsaParams.SERVER_PRIVATE_KEY,
                    "Not a usable EC or RSA private key (PKCS#8, PKCS#1 or SEC1 PEM expected): " + e.getMessage()));
        }
    }
}
