package io.github.iaroslavmolochkov.slsa.provenance.intoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.github.iaroslavmolochkov.slsa.provenance.slsa.SlsaPredicate;

import java.util.List;

/** An in-toto Statement v1 carrying the SLSA provenance predicate; the signed DSSE payload. */
public record InTotoStatement(
        @JsonProperty("_type") String type,
        List<Subject> subject,
        String predicateType,
        SlsaPredicate predicate) {

    public static final String TYPE = "https://in-toto.io/Statement/v1";
    public static final String SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1";
}
