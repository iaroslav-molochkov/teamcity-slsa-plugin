package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SignerConfig;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;

import java.util.Map;

/** Maps to the (empty) server-signer config. */
@Component
public class ServerConfigMapper implements ConfigMapper {

    @NotNull
    @Override
    public String signerId() {
        return SlsaParams.SIGNER_SERVER;
    }

    @NotNull
    @Override
    public SignerConfig map(@NotNull Map<String, String> params) {
        return ServerSignerConfig.INSTANCE;
    }
}
