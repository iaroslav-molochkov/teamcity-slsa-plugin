package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.sts;

import io.github.iaroslavmolochkov.teamcity.slsa.signing.dsse.DsseService;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.AbstractKmsSigningHandler;
import org.springframework.stereotype.Component;

/** KMS signing using credentials from assuming an IAM role via STS. */
@Component
public class AssumeRoleKmsSigningHandler extends AbstractKmsSigningHandler {

    public AssumeRoleKmsSigningHandler(AssumeRoleKmsClientLoader loader, DsseService dsse) {
        super(loader, dsse);
    }
}
