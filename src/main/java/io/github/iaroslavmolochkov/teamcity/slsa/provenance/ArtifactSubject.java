package io.github.iaroslavmolochkov.teamcity.slsa.provenance;

/** A build artifact as a SLSA subject: path, size, and SHA-256 of its content. */
public record ArtifactSubject(String path,
                              long size,
                              String sha256) {
}
