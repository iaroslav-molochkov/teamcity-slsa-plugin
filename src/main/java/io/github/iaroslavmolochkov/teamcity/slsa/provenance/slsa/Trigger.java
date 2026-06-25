package io.github.iaroslavmolochkov.teamcity.slsa.provenance.slsa;

/** The build's request origin: a user (with username and/or id), a snapshot dependency, or a trigger mechanism. */
public record Trigger(String type,
                      String username,
                      Long userId) {
}
