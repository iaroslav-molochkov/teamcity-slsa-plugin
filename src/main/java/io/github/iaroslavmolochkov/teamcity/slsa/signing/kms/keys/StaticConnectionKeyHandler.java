package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.keys;

import com.dynatrace.hash4j.hashing.HashStream128;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.AbstractConnectionKeyHandler;
import org.springframework.stereotype.Component;

/**
 * Static-keys connections are identified by region + access key id + secret. The stored (scrambled)
 * secret is used as-is: it's deterministic, so the same secret keys the same client, and distinct
 * secrets never collide — no need to unscramble just to derive an identity.
 */
@Component
public class StaticConnectionKeyHandler extends AbstractConnectionKeyHandler {

    private static final byte REGION = 1;
    private static final byte ACCESS_KEY_ID = 2;
    private static final byte SECRET = 3;

    @Override
    public SignerType type() {
        return SignerType.AWS_KMS_STATIC;
    }

    @Override
    protected void funnel(HashStream128 stream, SigningContext context) {
        put(stream, REGION, context.get(SlsaParams.REGION));
        put(stream, ACCESS_KEY_ID, context.get(SlsaParams.ACCESS_KEY_ID));
        put(stream, SECRET, context.get(SlsaParams.SECRET_ACCESS_KEY));
    }
}
