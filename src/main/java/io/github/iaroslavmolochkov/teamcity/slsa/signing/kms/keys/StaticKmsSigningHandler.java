package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.keys;

import io.github.iaroslavmolochkov.teamcity.slsa.signing.dsse.DsseService;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.AbstractKmsSigningHandler;
import org.springframework.stereotype.Component;

/** KMS signing using an explicit access key id + secret. */
@Component
public class StaticKmsSigningHandler extends AbstractKmsSigningHandler {

    public StaticKmsSigningHandler(StaticKmsClientLoader loader, DsseService dsse) {
        super(loader, dsse);
    }
}
