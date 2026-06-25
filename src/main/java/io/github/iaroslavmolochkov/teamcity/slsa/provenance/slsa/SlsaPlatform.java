package io.github.iaroslavmolochkov.teamcity.slsa.provenance.slsa;

import java.util.Map;

/** SLSA provenance {@code builder}: the build platform identity. */
public record SlsaPlatform(String id,
                           Map<String, String> version) {
}
