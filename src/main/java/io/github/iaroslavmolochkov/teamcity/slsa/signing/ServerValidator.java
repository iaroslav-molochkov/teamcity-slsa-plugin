package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/** The server-key signer needs no configuration, so its params are always valid. */
@Component
public class ServerValidator implements Validator {

    @NotNull
    @Override
    public String signerId() {
        return SlsaParams.SIGNER_SERVER;
    }

    @NotNull
    @Override
    public List<InvalidProperty> validate(@NotNull Map<String, String> params) {
        return List.of();
    }
}
