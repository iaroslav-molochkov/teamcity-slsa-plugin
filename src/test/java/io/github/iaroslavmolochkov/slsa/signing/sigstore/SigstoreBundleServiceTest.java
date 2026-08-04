package io.github.iaroslavmolochkov.slsa.signing.sigstore;

import io.github.iaroslavmolochkov.slsa.provenance.ProvenanceJsonHandler;
import io.github.iaroslavmolochkov.slsa.signing.dsse.DsseEnvelope;
import io.github.iaroslavmolochkov.slsa.signing.dsse.DsseSignature;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SigstoreBundleServiceTest {

    private static final DsseEnvelope ENVELOPE = new DsseEnvelope(
            "cGF5bG9hZA==",
            DsseEnvelope.IN_TOTO_PAYLOAD_TYPE,
            List.of(new DsseSignature("arn:aws:kms:eu-west-1:1:key/abc", "c2ln")));

    private final SigstoreBundleService service = new SigstoreBundleService();

    @Test
    void wrapsEnvelopeIntoBundleShape() {
        SigstoreBundle bundle = service.bundle(ENVELOPE);

        assertEquals(SigstoreBundle.MEDIA_TYPE, bundle.mediaType());
        assertEquals(ENVELOPE.payload(), bundle.dsseEnvelope().payload());
        assertEquals(ENVELOPE.payloadType(), bundle.dsseEnvelope().payloadType());
        assertEquals(List.of(new BundleSignature("c2ln")), bundle.dsseEnvelope().signatures());
    }

    @Test
    void carriesKeyIdAsHintOnly() {
        SigstoreBundle bundle = service.bundle(ENVELOPE);

        // cosign matches the signature against the supplied --key; a per-signature keyid it cannot match is rejected.
        assertEquals("arn:aws:kms:eu-west-1:1:key/abc", bundle.verificationMaterial().publicKey().hint());

        String json = new String(new ProvenanceJsonHandler().toBytes(bundle), StandardCharsets.UTF_8);
        assertTrue(json.contains("\"hint\":\"arn:aws:kms:eu-west-1:1:key/abc\""), json);
        assertFalse(json.contains("\"keyid\""), "keyid must not appear in the bundle's dsseEnvelope: " + json);
    }
}
