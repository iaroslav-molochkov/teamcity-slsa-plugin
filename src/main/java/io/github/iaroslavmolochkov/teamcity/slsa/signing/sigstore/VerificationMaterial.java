package io.github.iaroslavmolochkov.teamcity.slsa.signing.sigstore;

/**
 * The bundle's verification material. Carries only a {@code publicKey} hint (the signer's key id): cosign verifies
 * against the key supplied with {@code --key}, so the key is referenced, not embedded.
 */
public record VerificationMaterial(PublicKeyId publicKey) {

    /** A reference to the verifying key by its id; informational, since the verifier supplies the actual key. */
    public record PublicKeyId(String hint) {
    }
}
