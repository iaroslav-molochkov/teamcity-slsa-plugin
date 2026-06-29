package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.ProvenanceJsonHandler;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.dsse.DsseEnvelope;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.dsse.DsseService;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DsseServiceTest {

    private final DsseService dsse = new DsseService();


    @Test
    void paeMatchesDsseSpecExample() {
        byte[] pae = dsse.pae("http://example.com/HelloWorld", "hello world".getBytes(StandardCharsets.UTF_8));
        assertEquals("DSSEv1 29 http://example.com/HelloWorld 11 hello world",
                new String(pae, StandardCharsets.UTF_8));
    }

    @Test
    void paeUsesByteLengthNotCharLength() {
        byte[] pae = dsse.pae("t", "h\u00e9llo".getBytes(StandardCharsets.UTF_8));
        assertEquals("DSSEv1 1 t 6 h\u00e9llo", new String(pae, StandardCharsets.UTF_8));
    }

    @Test
    void paeFramingIsExactAsciiBytes() {
        byte[] pae = dsse.pae("application/vnd.in-toto+json", "x".getBytes(StandardCharsets.UTF_8));
        byte[] expected = "DSSEv1 28 application/vnd.in-toto+json 1 x".getBytes(StandardCharsets.US_ASCII);

        assertArrayEquals(expected, pae);
        for (byte b : pae) {
            assertTrue((b & 0xFF) < 0x80, "should be ASCII");
        }
    }

    @Test
    void paeEmbedsRawPayloadBytes() {
        byte[] payload = {0, 1, 2, 3};
        byte[] pae = dsse.pae("application/vnd.in-toto+json", payload);
        byte[] prefix = "DSSEv1 28 application/vnd.in-toto+json 4 ".getBytes(StandardCharsets.US_ASCII);
        byte[] tail = new byte[4];
        System.arraycopy(pae, pae.length - 4, tail, 0, 4);
        assertArrayEquals(payload, tail);
        byte[] head = new byte[prefix.length];
        System.arraycopy(pae, 0, head, 0, prefix.length);
        assertArrayEquals(prefix, head);
    }


    @Test
    void envelopeBase64EncodesPayloadAndSignature() {
        byte[] payload = "{\"_type\":\"x\"}".getBytes(StandardCharsets.UTF_8);
        byte[] signature = {10, 20, 30, 40};
        DsseEnvelope envelope = dsse.envelope(payload, "arn:aws:kms:key/abc", signature);

        assertArrayEquals(payload, Base64.getDecoder().decode(envelope.payload()));
        assertEquals(DsseEnvelope.IN_TOTO_PAYLOAD_TYPE, envelope.payloadType());
        assertEquals(1, envelope.signatures().size());
        assertEquals("arn:aws:kms:key/abc", envelope.keyId());
        assertArrayEquals(signature, Base64.getDecoder().decode(envelope.signatures().get(0).sig()));
    }

    @Test
    void envelopeSerializesToDsseJsonShape() throws Exception {
        DsseEnvelope envelope = dsse.envelope(
                "payload".getBytes(StandardCharsets.UTF_8), "keyid-1", new byte[]{1, 2, 3});

        JsonNode json = new ObjectMapper().readTree(new ProvenanceJsonHandler().toBytes(envelope));
        assertEquals(Base64.getEncoder().encodeToString("payload".getBytes(StandardCharsets.UTF_8)),
                json.get("payload").asText());
        assertEquals(DsseEnvelope.IN_TOTO_PAYLOAD_TYPE, json.get("payloadType").asText());
        assertEquals("keyid-1", json.get("signatures").get(0).get("keyid").asText());
        assertEquals(Base64.getEncoder().encodeToString(new byte[]{1, 2, 3}),
                json.get("signatures").get(0).get("sig").asText());
    }
}
