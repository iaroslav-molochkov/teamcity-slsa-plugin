package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.dcp;

import io.github.iaroslavmolochkov.teamcity.slsa.signing.dsse.DsseService;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.AbstractKmsSigningHandler;
import org.springframework.stereotype.Component;

/** KMS signing using the default provider chain. */
@Component
public class DefaultKmsSigningHandler extends AbstractKmsSigningHandler {

    public DefaultKmsSigningHandler(DefaultKmsClientLoader loader, DsseService dsse) {
        super(loader, dsse);
    }
}
