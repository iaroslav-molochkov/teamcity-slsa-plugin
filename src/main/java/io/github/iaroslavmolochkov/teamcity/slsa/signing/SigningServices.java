package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import org.springframework.stereotype.Component;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Routes a built payload to the {@link SigningService} for the context's signer type (map lookup, no
 * branching). Reached only after {@link Validators} has accepted the params, so the type resolves to a
 * registered service.
 */
@Component
public class SigningServices {

    private final Map<SignerType, SigningService> signingService = new EnumMap<>(SignerType.class);

    public SigningServices(List<SigningService> services) {
        for (SigningService service : services) {
            for (SignerType type : service.types()) {
                signingService.put(type, service);
            }
        }
    }

    public DsseEnvelope sign(SigningContext context, byte[] payload) {
        SigningService service = signingService.get(context.type());
        if (service == null) {
            throw new SigningException("No signing service for signer: " + context.type());
        }
        return service.sign(context, payload);
    }
}
