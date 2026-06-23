package io.github.iaroslavmolochkov.teamcity.slsa.provenance.slsa;

import java.util.List;
import java.util.Map;

/**
 * SLSA provenance {@code builder}: the build platform identity. {@code id} must be a
 * platform-controlled URI uniquely identifying the build platform.
 */
public record SlsaBuilder(String id, Map<String, String> version, List<Object> builderDependencies) {
}
