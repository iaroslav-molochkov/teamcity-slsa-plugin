package io.github.iaroslavmolochkov.teamcity.slsa.signing;

/** A single DSSE signature: the signing key id and the base64-encoded signature bytes. */
record Signature(String keyid, String sig) {
}
