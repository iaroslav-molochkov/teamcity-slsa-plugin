package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import jetbrains.buildServer.serverSide.InvalidProperty;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/** The server-key signer needs no configuration, so there is nothing to validate. */
@Component
public class ServerValidator implements Validator {

    @NotNull
    @Override
    public SignerType type() {
        return SignerType.SERVER;
    }

    @NotNull
    @Override
    public List<InvalidProperty> validate(@NotNull Map<String, String> params) {
        return List.of();
    }
}
