package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SignerConfig;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Creates a {@link Signer} for a validated {@link SignerConfig} by dispatching to the matching
 * {@link SignerFactory} (keyed on {@link SignerConfig#signerId()}).
 */
@Component
public class SignerFactories {

    private final Map<String, SignerFactory> factories = new HashMap<>();

    public SignerFactories(@NotNull List<SignerFactory> factories) {
        for (SignerFactory factory : factories) {
            this.factories.put(factory.signerId(), factory);
        }
    }

    @NotNull
    public Signer create(@NotNull SignerConfig config) {
        SignerFactory factory = factories.get(config.signerId());
        if (factory == null) {
            throw new IllegalStateException("No signer factory for '" + config.signerId() + "'");
        }
        return factory.create(config);
    }
}
