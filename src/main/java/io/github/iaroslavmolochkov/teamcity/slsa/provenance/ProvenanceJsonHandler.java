package io.github.iaroslavmolochkov.teamcity.slsa.provenance;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.springframework.stereotype.Component;

/**
 * Serializes provenance/DSSE payloads to JSON. Configured {@code NON_EMPTY}: null, empty strings, and
 * empty (or all-empty) collections are omitted. This is the single place that decides field omission -
 * builders just put what they have and never gate on null/emptiness themselves.
 */
@Component
public class ProvenanceJsonHandler {

    private static final ObjectMapper mapper = new ObjectMapper()
            .setSerializationInclusion(JsonInclude.Include.NON_EMPTY)
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);

    /** Serializes the given value to UTF-8 JSON bytes. */
    public byte[] toBytes(Object value) {
        try {
            return mapper.writeValueAsBytes(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize provenance JSON", e);
        }
    }
}
