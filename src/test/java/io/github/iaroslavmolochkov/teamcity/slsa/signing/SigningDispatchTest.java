package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SigningDispatchTest {

    private record StubValidator(@NotNull SignerType type, @NotNull List<InvalidProperty> errors) implements Validator {
        @NotNull
        @Override
        public List<InvalidProperty> validate(@NotNull Map<String, String> params) {
            return errors;
        }
    }

    private record StubService(@NotNull Set<SignerType> types, @NotNull DsseEnvelope envelope) implements SigningService {
        @NotNull
        @Override
        public DsseEnvelope sign(@NotNull Map<String, String> params, @NotNull byte[] payload) {
            return envelope;
        }
    }

    private static final DsseEnvelope ENVELOPE = new Dsse().envelope(new byte[]{1}, "key", new byte[]{2});

    // --- Validators ---

    private Validators validators(List<InvalidProperty> serverErrors) {
        return new Validators(List.of(new StubValidator(SignerType.SERVER, serverErrors)));
    }

    @Test
    void requiresSignerSelection() {
        assertEquals(SlsaParams.SIGNER, validators(List.of()).validate(Map.of()).get(0).getPropertyName());
    }

    @Test
    void rejectsUnknownSigner() {
        assertFalse(validators(List.of()).validate(Map.of(SlsaParams.SIGNER, "nope")).isEmpty());
    }

    @Test
    void delegatesValidationToSelectedValidator() {
        assertTrue(validators(List.of()).validate(Map.of(SlsaParams.SIGNER, "server")).isEmpty());
        assertFalse(validators(List.of(new InvalidProperty("x", "bad")))
                .validate(Map.of(SlsaParams.SIGNER, "server")).isEmpty());
    }

    // --- SigningServices ---

    private SigningServices services() {
        return new SigningServices(List.of(new StubService(Set.of(SignerType.SERVER), ENVELOPE)));
    }

    @Test
    void routesPayloadToServiceByType() {
        assertSame(ENVELOPE, services().sign(Map.of(SlsaParams.SIGNER, "server"), new byte[]{0}));
    }

    @Test
    void throwsWhenNoServiceForType() {
        assertThrows(SigningException.class, () -> services().sign(Map.of(SlsaParams.SIGNER, "nope"), new byte[]{0}));
    }
}
