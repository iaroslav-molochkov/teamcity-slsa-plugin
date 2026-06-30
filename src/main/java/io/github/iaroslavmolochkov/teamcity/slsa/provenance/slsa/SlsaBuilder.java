package io.github.iaroslavmolochkov.teamcity.slsa.provenance.slsa;

import java.util.Map;

/** SLSA provenance {@code builder}: the builder platform identity. */
public record SlsaBuilder(String id,
                          Map<String, String> version) {
}
