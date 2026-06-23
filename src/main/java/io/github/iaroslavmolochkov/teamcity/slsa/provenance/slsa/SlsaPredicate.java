package io.github.iaroslavmolochkov.teamcity.slsa.provenance.slsa;

/**
 * The <a href="https://slsa.dev/spec/v1.0/provenance">SLSA v1.0 provenance</a> predicate.
 * Null/empty members are dropped on serialization.
 */
public record SlsaPredicate(BuildDefinition buildDefinition, RunDetails runDetails) {
}
