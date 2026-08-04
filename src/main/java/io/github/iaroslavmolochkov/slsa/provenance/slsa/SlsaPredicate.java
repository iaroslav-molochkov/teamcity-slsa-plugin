package io.github.iaroslavmolochkov.slsa.provenance.slsa;

/** The SLSA v1.0 provenance predicate. */
public record SlsaPredicate(BuildDefinition buildDefinition,
                            RunDetails runDetails) {
}
