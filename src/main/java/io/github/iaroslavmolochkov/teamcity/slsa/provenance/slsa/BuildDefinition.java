package io.github.iaroslavmolochkov.teamcity.slsa.provenance.slsa;

import java.util.List;
import java.util.Map;

/** SLSA provenance {@code buildDefinition}: what was built and from which inputs. */
public record BuildDefinition(
        String buildType,
        Map<String, Object> externalParameters,
        Map<String, Object> internalParameters,
        List<ResolvedDependency> resolvedDependencies) {
}
