package io.github.iaroslavmolochkov.teamcity.slsa.signing.server;

import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.Validator;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.springframework.stereotype.Component;

import java.util.List;

/** The server-key signer needs no configuration, so there is nothing to validate. */
@Component
public class ServerValidator implements Validator {

    @Override
    public SignerType type() {
        return SignerType.SERVER;
    }

    @Override
    public List<InvalidProperty> validate(SigningContext context) {
        return List.of();
    }
}
