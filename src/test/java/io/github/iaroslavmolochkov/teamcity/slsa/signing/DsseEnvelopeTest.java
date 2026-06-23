package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.ProvenanceJson;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class DsseEnvelopeTest {

    @Test
    void base64EncodesPayloadAndSignature() {
        byte[] payload = "{\"_type\":\"x\"}".getBytes(StandardCharsets.UTF_8);
        byte[] signature = {10, 20, 30, 40};
        DsseEnvelope envelope = DsseEnvelope.of(payload, "arn:aws:kms:key/abc", signature);

        assertArrayEquals(payload, Base64.getDecoder().decode(envelope.payload()));
        assertEquals(DsseEnvelope.IN_TOTO_PAYLOAD_TYPE, envelope.payloadType());
        assertEquals(1, envelope.signatures().size());
        assertEquals("arn:aws:kms:key/abc", envelope.signatures().get(0).keyid());
        assertArrayEquals(signature, Base64.getDecoder().decode(envelope.signatures().get(0).sig()));
    }

    @Test
    void serializesToDsseJsonShape() throws Exception {
        DsseEnvelope envelope = DsseEnvelope.of(
                "payload".getBytes(StandardCharsets.UTF_8), "keyid-1", new byte[]{1, 2, 3});

        JsonNode json = ProvenanceJson.mapper().readTree(ProvenanceJson.toBytes(envelope));
        assertEquals(Base64.getEncoder().encodeToString("payload".getBytes(StandardCharsets.UTF_8)),
                json.get("payload").asText());
        assertEquals(DsseEnvelope.IN_TOTO_PAYLOAD_TYPE, json.get("payloadType").asText());
        assertEquals("keyid-1", json.get("signatures").get(0).get("keyid").asText());
        assertEquals(Base64.getEncoder().encodeToString(new byte[]{1, 2, 3}),
                json.get("signatures").get(0).get("sig").asText());
    }
}
