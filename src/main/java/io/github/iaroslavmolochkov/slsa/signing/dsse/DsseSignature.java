package io.github.iaroslavmolochkov.slsa.signing.dsse;

/** A single DSSE signature: the signing key id and the base64-encoded signature bytes. */
public record DsseSignature(String keyid, String sig) {
}
