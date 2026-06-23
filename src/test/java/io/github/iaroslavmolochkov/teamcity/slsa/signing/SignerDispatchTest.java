package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SignerConfig;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignerDispatchTest {

    private record StubConfig(@NotNull String signerId) implements SignerConfig {}

    private record StubValidator(@NotNull String signerId, @NotNull List<InvalidProperty> errors) implements Validator {
        @NotNull
        @Override
        public List<InvalidProperty> validate(@NotNull Map<String, String> params) {
            return errors;
        }
    }

    private record StubMapper(@NotNull String signerId, @NotNull SignerConfig config) implements ConfigMapper {
        @NotNull
        @Override
        public SignerConfig map(@NotNull Map<String, String> params) {
            return config;
        }
    }

    private record StubFactory(@NotNull String signerId, @NotNull Signer signer) implements SignerFactory {
        @NotNull
        @Override
        public Signer create(@NotNull SignerConfig config) {
            return signer;
        }
    }

    @Test
    void validatorsRequireSignerSelection() {
        Validators validators = new Validators(List.of(new StubValidator("server", List.of())));
        assertEquals(SlsaParams.SIGNER, validators.validate(Map.of()).get(0).getPropertyName());
    }

    @Test
    void validatorsRejectUnknownSigner() {
        Validators validators = new Validators(List.of(new StubValidator("server", List.of())));
        assertFalse(validators.validate(Map.of(SlsaParams.SIGNER, "nope")).isEmpty());
    }

    @Test
    void validatorsDelegateToSelected() {
        Validators validators = new Validators(List.of(new StubValidator("server", List.of())));
        assertTrue(validators.validate(Map.of(SlsaParams.SIGNER, "server")).isEmpty());
    }

    @Test
    void mappersReturnConfigWhenValid() {
        StubConfig config = new StubConfig("server");
        Validators validators = new Validators(List.of(new StubValidator("server", List.of())));
        ConfigMappers mappers = new ConfigMappers(List.of(new StubMapper("server", config)), validators);

        ConfigResult<SignerConfig> result = mappers.map(Map.of(SlsaParams.SIGNER, "server"));
        assertTrue(result.isValid());
        assertSame(config, result.config());
    }

    @Test
    void mappersReturnErrorsWhenInvalid() {
        Validators validators = new Validators(
                List.of(new StubValidator("server", List.of(new InvalidProperty("x", "bad")))));
        ConfigMappers mappers = new ConfigMappers(List.of(new StubMapper("server", new StubConfig("server"))), validators);

        assertFalse(mappers.map(Map.of(SlsaParams.SIGNER, "server")).isValid());
    }

    @Test
    void factoriesRouteByConfigSignerId() {
        Signer signer = payload -> { throw new UnsupportedOperationException(); };
        SignerFactories factories = new SignerFactories(List.of(new StubFactory("server", signer)));

        assertSame(signer, factories.create(new StubConfig("server")));
        assertThrows(IllegalStateException.class, () -> factories.create(new StubConfig("nope")));
    }
}
