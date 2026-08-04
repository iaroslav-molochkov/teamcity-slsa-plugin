package io.github.iaroslavmolochkov.slsa.provenance.slsa;

/** SLSA provenance {@code runDetails.metadata}. Timestamps are RFC 3339 / ISO-8601 instants. */
public record RunMetadata(String invocationId,
                          String startedOn,
                          String finishedOn) {
}
