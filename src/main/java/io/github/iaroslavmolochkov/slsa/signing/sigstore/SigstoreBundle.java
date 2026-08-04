package io.github.iaroslavmolochkov.slsa.signing.sigstore;

/**
 * A Sigstore bundle (v0.3) carrying the signed DSSE envelope, published as the {@code provenance.sigstore.json}
 * artifact so it verifies directly with {@code cosign verify-blob-attestation --key}.
 */
public record SigstoreBundle(String mediaType, VerificationMaterial verificationMaterial, BundleEnvelope dsseEnvelope) {

    public static final String MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json";
}
