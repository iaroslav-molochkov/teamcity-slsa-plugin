package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Base64;
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

    /**
     * Builds an envelope from the raw payload bytes and a single raw signature, base64-encoding both.
     */
    @NotNull
    public static DsseEnvelope of(@NotNull byte[] payloadBytes, @NotNull String keyId, @NotNull byte[] signature) {
        Base64.Encoder b64 = Base64.getEncoder();
        return new DsseEnvelope(
                b64.encodeToString(payloadBytes),
                IN_TOTO_PAYLOAD_TYPE,
                List.of(new Signature(keyId, b64.encodeToString(signature))));
    }

    /** The first signature's key id, or {@code null} if unsigned. Avoids exposing {@link Signature}. */
    @Nullable
    public String keyId() {
        return signatures.isEmpty() ? null : signatures.get(0).keyid();
    }
}
