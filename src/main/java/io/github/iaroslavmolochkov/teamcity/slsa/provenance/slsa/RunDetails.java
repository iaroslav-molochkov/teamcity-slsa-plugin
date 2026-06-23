package io.github.iaroslavmolochkov.teamcity.slsa.provenance.slsa;

import java.util.List;

/** SLSA provenance {@code runDetails}: who ran the build and the run's metadata. */
public record RunDetails(SlsaBuilder builder, RunMetadata metadata, List<Object> byproducts) {
}
