package io.github.iaroslavmolochkov.teamcity.slsa.signing;


import java.util.List;

/** A DSSE envelope: the signed wrapper around the in-toto payload, serialized as the {@code .intoto.jsonl} line. */
public record DsseEnvelope(String payload, String payloadType, List<Signature> signatures) {

    public static final String IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json";

    /** The first signature's key id, or {@code null} if unsigned. Avoids exposing {@link Signature}. */
    public String keyId() {
        return signatures.isEmpty() ? null : signatures.get(0).keyid();
    }
}
