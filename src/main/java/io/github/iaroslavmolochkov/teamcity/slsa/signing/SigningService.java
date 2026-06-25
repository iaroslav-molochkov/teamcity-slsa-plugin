package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.signing.dsse.DsseEnvelope;
import org.springframework.stereotype.Component;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/** Routes a payload to the {@link SigningHandler} for the context's signer type. */
@Component
public class SigningService {

    private final Map<SignerType, SigningHandler> signingService = new EnumMap<>(SignerType.class);

    public SigningService(List<SigningHandler> handlers) {
        for (SigningHandler handler : handlers) {
            signingService.put(handler.type(), handler);
        }
    }

    public DsseEnvelope sign(SigningContext context, byte[] payload) {
        SigningHandler service = signingService.get(context.signerType());

        if (service == null) {
            throw new SigningException("No signing service for signer: " + context.signerType());
        }

        return service.sign(context, payload);
    }
}
