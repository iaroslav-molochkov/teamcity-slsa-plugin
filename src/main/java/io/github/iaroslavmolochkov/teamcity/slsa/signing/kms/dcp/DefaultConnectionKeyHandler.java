package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.dcp;

import com.dynatrace.hash4j.hashing.HashStream128;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.AbstractConnectionKeyHandler;
import org.springframework.stereotype.Component;

/** Default-provider-chain connections are identified by region alone (creds come from the environment). */
@Component
public class DefaultConnectionKeyHandler extends AbstractConnectionKeyHandler {

    private static final byte REGION = 1;

    @Override
    public SignerType type() {
        return SignerType.AWS_KMS_DEFAULT;
    }

    @Override
    protected void funnel(HashStream128 stream, SigningContext context) {
        put(stream, REGION, context.get(SlsaParams.REGION));
    }
}
