package io.github.iaroslavmolochkov.teamcity.slsa.provenance;

/**
 * A single build artifact described the way SLSA provenance does: by its path
 * within the build, its size, and the SHA-256 digest of its content.
 *
 * @param path   relative path of the artifact within the build's artifact tree
 * @param size   size in bytes
 * @param sha256 lowercase hex SHA-256 digest of the artifact content
 */
public record ArtifactSubject(String path, long size, String sha256) {
}
