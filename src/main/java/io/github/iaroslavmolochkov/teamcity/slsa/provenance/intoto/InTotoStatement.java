package io.github.iaroslavmolochkov.teamcity.slsa.provenance.intoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.slsa.SlsaPredicate;

import java.util.List;

/**
 * An <a href="https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md">in-toto
 * Statement v1</a> carrying a SLSA provenance predicate. This is the payload that gets
 * base64-encoded into the DSSE envelope and signed.
 */
public record InTotoStatement(
        @JsonProperty("_type") String type,
        List<Subject> subject,
        String predicateType,
        SlsaPredicate predicate) {

    public static final String TYPE = "https://in-toto.io/Statement/v1";
    public static final String SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1";

    public static InTotoStatement of(List<Subject> subjects, SlsaPredicate predicate) {
        return new InTotoStatement(TYPE, subjects, SLSA_PREDICATE_TYPE, predicate);
    }
}
