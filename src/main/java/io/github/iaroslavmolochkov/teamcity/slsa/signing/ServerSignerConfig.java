package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SignerConfig;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import org.jetbrains.annotations.NotNull;

/** The server-key signer needs no configuration. */
public record ServerSignerConfig() implements SignerConfig {

    public static final ServerSignerConfig INSTANCE = new ServerSignerConfig();

    @NotNull
    @Override
    public String signerId() {
        return SlsaParams.SIGNER_SERVER;
    }
}
