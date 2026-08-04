package io.github.iaroslavmolochkov.slsa.provenance.slsa;

import java.util.List;

/** SLSA provenance {@code buildDefinition}: what was built and from which inputs. */
public record BuildDefinition(
        String buildType,
        ExternalParameters externalParameters,
        InternalParameters internalParameters,
        List<ResolvedDependency> resolvedDependencies) {
}
