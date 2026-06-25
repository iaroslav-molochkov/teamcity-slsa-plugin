package io.github.iaroslavmolochkov.teamcity.slsa.provenance.slsa;

/** The SLSA v1.0 provenance predicate. */
public record SlsaPredicate(BuildDefinition buildDefinition,
                            RunDetails runDetails) {
}
