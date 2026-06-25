package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.credentials.keys;

import com.dynatrace.hash4j.hashing.HashStream128;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.AbstractConnectionKeyHandler;
import org.springframework.stereotype.Component;

/** Static-keys connections are distinguished by their access key id + secret (region and any role are shared). */
@Component
public class StaticConnectionKeyHandler extends AbstractConnectionKeyHandler {

    private static final byte ACCESS_KEY_ID = 6;
    private static final byte SECRET = 7;

    @Override
    public SignerType type() {
        return SignerType.AWS_KMS_STATIC;
    }

    @Override
    protected void funnel(HashStream128 stream, SigningContext context) {
        put(stream, ACCESS_KEY_ID, context.get(SlsaParams.ACCESS_KEY_ID));
        put(stream, SECRET, context.get(SlsaParams.SECRET_ACCESS_KEY));
    }
}
