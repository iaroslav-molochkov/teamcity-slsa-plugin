package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignerDispatchTest {

    /** A resolver that records nothing and returns canned results. */
    private record StubResolver(@NotNull SignerType type, @NotNull List<InvalidProperty> errors,
                                @NotNull Signer signer) implements SignerResolver {
        @NotNull
        @Override
        public List<InvalidProperty> validate(@NotNull Map<String, String> params) {
            return errors;
        }

        @NotNull
        @Override
        public Result<Signer> resolve(@NotNull Map<String, String> params) {
            return errors.isEmpty() ? Result.of(signer) : Result.invalid(errors);
        }
    }

    private static final Signer DUMMY = new Signer() {
        @NotNull
        @Override
        public SignerType type() {
            return SignerType.SERVER;
        }

        @NotNull
        @Override
        public DsseEnvelope sign(@NotNull byte[] payload) {
            throw new UnsupportedOperationException();
        }
    };

    private SignerHandler handler(List<InvalidProperty> serverErrors) {
        return new SignerHandler(List.of(new StubResolver(SignerType.SERVER, serverErrors, DUMMY)));
    }

    @Test
    void requiresSignerSelection() {
        assertEquals(SlsaParams.SIGNER, handler(List.of()).validate(Map.of()).get(0).getPropertyName());
    }

    @Test
    void rejectsUnknownSigner() {
        assertFalse(handler(List.of()).validate(Map.of(SlsaParams.SIGNER, "nope")).isEmpty());
    }

    @Test
    void delegatesValidationToSelectedResolver() {
        assertTrue(handler(List.of()).validate(Map.of(SlsaParams.SIGNER, "server")).isEmpty());
    }

    @Test
    void resolveReturnsSignerWhenValid() {
        Result<Signer> result = handler(List.of()).resolve(Map.of(SlsaParams.SIGNER, "server"));
        assertTrue(result.isValid());
        assertSame(DUMMY, result.value());
    }

    @Test
    void resolveReturnsErrorsWhenInvalid() {
        SignerHandler handler = handler(List.of(new InvalidProperty("x", "bad")));
        assertFalse(handler.resolve(Map.of(SlsaParams.SIGNER, "server")).isValid());
    }
}
