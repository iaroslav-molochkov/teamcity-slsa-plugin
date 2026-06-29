package io.github.iaroslavmolochkov.teamcity.slsa.provenance.slsa;

/** SLSA provenance {@code runDetails}: who ran the build and the run's metadata. */
public record RunDetails(SlsaBuilder builder,
                         RunMetadata metadata) {
}
