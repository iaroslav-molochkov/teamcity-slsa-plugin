package io.github.iaroslavmolochkov.teamcity.slsa.signing.dsse;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/** A DSSE envelope: the signed wrapper around the in-toto payload, serialized as the {@code .intoto.jsonl} line. */
public record DsseEnvelope(String payload, String payloadType,
                           @JsonProperty("signatures") List<DsseSignature> dsseSignatures) {

    public static final String IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json";

    public String keyId() {
        return dsseSignatures.isEmpty() ? null : dsseSignatures.getFirst().keyid();
    }
}
