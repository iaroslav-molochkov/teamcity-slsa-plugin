package io.github.iaroslavmolochkov.teamcity.slsa.provenance;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.springframework.stereotype.Component;

/** Serializes provenance/DSSE payloads to JSON, omitting empty values. */
@Component
public class ProvenanceJsonHandler {

    private static final ObjectMapper mapper = new ObjectMapper()
            .setSerializationInclusion(JsonInclude.Include.NON_EMPTY)
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);

    public byte[] toBytes(Object value) {
        try {
            return mapper.writeValueAsBytes(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize provenance JSON", e);
        }
    }
}
