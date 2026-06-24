package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.sts;

import com.dynatrace.hash4j.hashing.HashStream128;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.AbstractConnectionKeyHandler;
import org.springframework.stereotype.Component;

/**
 * Assume-role connections are identified by region + role ARN + external id + STS endpoint — the inputs
 * that determine which STS client and assumed identity back the KMS client. Session name and duration are
 * per-request details, not connection identity, so they're excluded.
 */
@Component
public class AssumeRoleConnectionKeyHandler extends AbstractConnectionKeyHandler {

    private static final byte REGION = 1;
    private static final byte ROLE_ARN = 2;
    private static final byte EXTERNAL_ID = 3;
    private static final byte STS_ENDPOINT = 4;

    @Override
    public SignerType type() {
        return SignerType.AWS_KMS_ASSUME_ROLE;
    }

    @Override
    protected void funnel(HashStream128 stream, SigningContext context) {
        put(stream, REGION, context.get(SlsaParams.REGION));
        put(stream, ROLE_ARN, context.get(SlsaParams.ASSUME_ROLE_ARN));
        put(stream, EXTERNAL_ID, context.get(SlsaParams.ASSUME_ROLE_EXTERNAL_ID));
        put(stream, STS_ENDPOINT, context.get(SlsaParams.STS_ENDPOINT));
    }
}
