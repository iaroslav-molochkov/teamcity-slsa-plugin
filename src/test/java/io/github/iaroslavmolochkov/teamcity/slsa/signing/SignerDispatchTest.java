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

    /** A processor that records nothing and returns canned results. */
    private record StubProcessor(@NotNull SignerType type, @NotNull List<InvalidProperty> errors,
                                 @NotNull Signer signer) implements SignerProcessor {
        @NotNull
        @Override
        public List<InvalidProperty> validate(@NotNull Map<String, String> params) {
            return errors;
        }

        @NotNull
        @Override
        public Result<Signer> process(@NotNull Map<String, String> params) {
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
        return new SignerHandler(List.of(new StubProcessor(SignerType.SERVER, serverErrors, DUMMY)));
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
    void delegatesValidationToSelectedProcessor() {
        assertTrue(handler(List.of()).validate(Map.of(SlsaParams.SIGNER, "server")).isEmpty());
    }

    @Test
    void processReturnsSignerWhenValid() {
        Result<Signer> result = handler(List.of()).process(Map.of(SlsaParams.SIGNER, "server"));
        assertTrue(result.isValid());
        assertSame(DUMMY, result.value());
    }

    @Test
    void processReturnsErrorsWhenInvalid() {
        SignerHandler handler = handler(List.of(new InvalidProperty("x", "bad")));
        assertFalse(handler.process(Map.of(SlsaParams.SIGNER, "server")).isValid());
    }
}
