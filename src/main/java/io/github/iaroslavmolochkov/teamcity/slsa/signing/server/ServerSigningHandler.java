package io.github.iaroslavmolochkov.teamcity.slsa.signing.server;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.dsse.DsseEnvelope;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.dsse.DsseService;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningException;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningHandler;
import org.springframework.stereotype.Component;

import java.security.GeneralSecurityException;
import java.security.Signature;
import java.util.Set;

/** Signs the DSSE PAE with the PEM private key read from the server-side path in the feature config; stateless. */
@Component
public class ServerSigningHandler implements SigningHandler {

    private final ServerKeyParser keyParser;
    private final DsseService dsse;

    public ServerSigningHandler(ServerKeyParser keyParser, DsseService dsse) {
        this.keyParser = keyParser;
        this.dsse = dsse;
    }

    @Override
    public SignerType type() {
        return SignerType.SERVER;
    }

    @Override
    public DsseEnvelope sign(SigningContext context, byte[] payload) {
        ServerKey key = keyParser.fromPath(context.get(SlsaParams.SERVER_PRIVATE_KEY_PATH));
        byte[] pae = dsse.pae(DsseEnvelope.IN_TOTO_PAYLOAD_TYPE, payload);

        try {
            Signature signer = Signature.getInstance(key.signatureAlgorithm());
            signer.initSign(key.privateKey());
            signer.update(pae);

            return dsse.envelope(payload, key.keyId(), signer.sign());
        } catch (GeneralSecurityException e) {
            throw new SigningException("Server-side signing failed", e);
        }
    }
}
