package io.github.iaroslavmolochkov.teamcity.slsa.signing.dsse;

import java.util.List;

/** A DSSE envelope: the signed wrapper around the in-toto payload, serialized as the {@code .intoto.jsonl} line. */
public record DsseEnvelope(String payload, String payloadType, List<DsseSignature> signatures) {

    public static final String IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json";

    public String keyId() {
        return signatures.isEmpty() ? null : signatures.getFirst().keyid();
    }
}
