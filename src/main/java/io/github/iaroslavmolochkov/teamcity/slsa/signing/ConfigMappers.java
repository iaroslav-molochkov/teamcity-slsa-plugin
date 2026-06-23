package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SignerConfig;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Turns raw feature params into a validated {@link SignerConfig}: validates via {@link Validators},
 * then — only if clean — dispatches to the selected signer's {@link ConfigMapper}. The build-time
 * entry point; an invalid result carries the same errors the UI would show.
 */
@Component
public class ConfigMappers {

    private final Map<String, ConfigMapper> mappers = new HashMap<>();
    private final Validators validators;

    public ConfigMappers(@NotNull List<ConfigMapper> mappers, @NotNull Validators validators) {
        this.validators = validators;
        for (ConfigMapper mapper : mappers) {
            this.mappers.put(mapper.signerId(), mapper);
        }
    }

    @NotNull
    public ConfigResult<SignerConfig> map(@NotNull Map<String, String> params) {
        List<InvalidProperty> errors = validators.validate(params);

        if (!errors.isEmpty()) {
            return ConfigResult.invalid(errors);
        }

        ConfigMapper mapper = mappers.get(SlsaParams.signerId(params));

        return ConfigResult.of(mapper.map(params));
    }
}
