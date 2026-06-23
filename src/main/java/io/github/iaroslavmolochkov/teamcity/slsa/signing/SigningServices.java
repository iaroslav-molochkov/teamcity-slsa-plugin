package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.util.Params;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Routes a built payload to the {@link SigningService} for the params' signer type (map lookup, no
 * branching). Reached only after {@link Validators} has accepted the params, so the type resolves to a
 * registered service.
 */
@Component
public class SigningServices {

    private final Map<SignerType, SigningService> byType = new EnumMap<>(SignerType.class);

    public SigningServices(@NotNull List<SigningService> services) {
        for (SigningService service : services) {
            for (SignerType type : service.types()) {
                byType.put(type, service);
            }
        }
    }

    @NotNull
    public DsseEnvelope sign(@NotNull Map<String, String> params, @NotNull byte[] payload) {
        SignerType type = SignerType.fromValue(Params.get(params, SlsaParams.SIGNER));
        SigningService service = byType.get(type);
        if (service == null) {
            throw new SigningException("No signing service for signer: " + Params.get(params, SlsaParams.SIGNER));
        }
        return service.sign(params, payload);
    }
}
