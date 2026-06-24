package io.github.iaroslavmolochkov.teamcity.slsa.signing;


import java.util.List;

/**
 * A <a href="https://github.com/secure-systems-lab/dsse">DSSE</a> envelope: the signed wrapper
 * around the in-toto provenance payload. Serialized to JSON it is the {@code .intoto.jsonl} line.
 *
 * @param payload     base64 of the in-toto Statement JSON bytes (the exact bytes that were signed)
 * @param payloadType the in-toto media type
 * @param signatures  one or more signatures over {@code PAE(payloadType, payload-bytes)}
 */
public record DsseEnvelope(String payload, String payloadType, List<Signature> signatures) {

    public static final String IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json";

    /** The first signature's key id, or {@code null} if unsigned. Avoids exposing {@link Signature}. */
    public String keyId() {
        return signatures.isEmpty() ? null : signatures.get(0).keyid();
    }
}
