package io.github.iaroslavmolochkov.slsa.provenance.slsa;

/** SLSA {@code internalParameters}: platform-established values. Absent fields are omitted on serialization. */
public record InternalParameters(
        String buildNumber,
        String agentName,
        String agentHostName,
        String agentVersion,
        String agentOs,
        Boolean agentIsCloud,
        Trigger trigger) {
}
