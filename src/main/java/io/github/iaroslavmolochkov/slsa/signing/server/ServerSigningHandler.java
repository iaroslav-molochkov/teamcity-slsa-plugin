package io.github.iaroslavmolochkov.slsa.signing.server;

import io.github.iaroslavmolochkov.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.slsa.signing.dsse.DsseEnvelope;
import io.github.iaroslavmolochkov.slsa.signing.dsse.DsseService;
import io.github.iaroslavmolochkov.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.slsa.signing.SigningContext;
import io.github.iaroslavmolochkov.slsa.signing.SigningException;
import io.github.iaroslavmolochkov.slsa.signing.SigningHandler;
import org.springframework.stereotype.Component;

import java.security.GeneralSecurityException;
import java.security.Signature;

/** Signs the DSSE PAE with the named PEM private key from the server key store; stateless. */
@Component
public class ServerSigningHandler implements SigningHandler {

    private final ServerKeyStore keyStore;
    private final ServerKeyParser keyParser;
    private final DsseService dsse;

    public ServerSigningHandler(ServerKeyStore keyStore, ServerKeyParser keyParser, DsseService dsse) {
        this.keyStore = keyStore;
        this.keyParser = keyParser;
        this.dsse = dsse;
    }

    @Override
    public SignerType type() {
        return SignerType.SERVER;
    }

    @Override
    public DsseEnvelope sign(SigningContext context, byte[] payload) {
        ServerKey key = keyParser.parse(keyStore.read(context.get(SlsaParams.SERVER_KEY_NAME)));
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
