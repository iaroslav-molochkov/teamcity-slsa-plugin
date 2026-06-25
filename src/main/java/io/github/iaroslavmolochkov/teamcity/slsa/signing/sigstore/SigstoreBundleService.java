package io.github.iaroslavmolochkov.teamcity.slsa.signing.sigstore;

import io.github.iaroslavmolochkov.teamcity.slsa.signing.dsse.DsseEnvelope;
import org.springframework.stereotype.Component;

import java.util.List;

/** Wraps a signed {@link DsseEnvelope} into a Sigstore bundle for {@code cosign verify-blob-attestation}. */
@Component
public class SigstoreBundleService {

    public SigstoreBundle bundle(DsseEnvelope envelope) {
        List<BundleSignature> signatures = envelope.signatures()
                .stream()
                .map(signature -> new BundleSignature(signature.sig()))
                .toList();
        return new SigstoreBundle(
                SigstoreBundle.MEDIA_TYPE,
                new VerificationMaterial(new VerificationMaterial.PublicKeyId(envelope.keyId())),
                new BundleEnvelope(envelope.payload(), envelope.payloadType(), signatures));
    }
}
