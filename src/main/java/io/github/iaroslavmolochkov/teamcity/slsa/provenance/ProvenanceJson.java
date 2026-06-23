package io.github.iaroslavmolochkov.teamcity.slsa.provenance;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

/**
 * Shared JSON serialization for provenance/DSSE payloads.
 *
 * <p>DSSE does not require canonical JSON: we sign the exact bytes produced here and base64 those
 * same bytes into the envelope. A verifier base64-decodes the payload and re-runs PAE over it — it
 * never re-serializes — so a single, stable serialization is all that's needed.
 */
public final class ProvenanceJson {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            // Drop null and empty members so the predicate stays compact and matches SLSA examples.
            .setSerializationInclusion(JsonInclude.Include.NON_EMPTY)
            // Deterministic output (sorted map keys) so attestations are stable/diffable; this is why
            // the builder can use plain HashMaps instead of LinkedHashMaps.
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);

    private ProvenanceJson() {
    }

    /** Serializes the given value to UTF-8 JSON bytes. */
    public static byte[] toBytes(Object value) {
        try {
            return MAPPER.writeValueAsBytes(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize provenance JSON", e);
        }
    }

    public static ObjectMapper mapper() {
        return MAPPER;
    }
}
