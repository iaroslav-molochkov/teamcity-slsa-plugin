package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.credentials.dcp;

import com.dynatrace.hash4j.hashing.HashStream128;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.AbstractConnectionKeyHandler;
import org.springframework.stereotype.Component;

/** Default-provider-chain connections add no base-specific fields; region and any role come from the shared scheme. */
@Component
public class DefaultConnectionKeyHandler extends AbstractConnectionKeyHandler {

    @Override
    public SignerType type() {
        return SignerType.AWS_KMS_DEFAULT;
    }

    @Override
    protected void funnel(HashStream128 stream, SigningContext context) {
    }
}
