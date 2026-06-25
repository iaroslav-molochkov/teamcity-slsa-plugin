package io.github.iaroslavmolochkov.teamcity.slsa.signing.sigstore;

import java.util.List;

/** The DSSE envelope as carried inside a Sigstore bundle: the same payload and signatures, without the {@code keyid}. */
public record BundleEnvelope(String payload, String payloadType, List<BundleSignature> signatures) {
}
