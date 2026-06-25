package io.github.iaroslavmolochkov.teamcity.slsa.signing.sigstore;

/**
 * A signature within a Sigstore bundle: the base64-encoded signature bytes only. The per-signature {@code keyid} is
 * deliberately omitted, since cosign rejects a signature whose keyid it cannot match to the supplied key.
 */
public record BundleSignature(String sig) {
}
