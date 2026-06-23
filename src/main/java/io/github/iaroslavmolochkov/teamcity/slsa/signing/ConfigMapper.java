package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SignerConfig;
import org.jetbrains.annotations.NotNull;

import java.util.Map;

/**
 * Maps a signer's raw build-feature params into its typed {@link SignerConfig}. Runs only after the
 * matching {@link Validator} has passed, so it may trust that required params are present and valid.
 * Selected by {@link #signerId()}.
 */
public interface ConfigMapper {

    @NotNull
    String signerId();

    @NotNull
    SignerConfig map(@NotNull Map<String, String> params);
}
