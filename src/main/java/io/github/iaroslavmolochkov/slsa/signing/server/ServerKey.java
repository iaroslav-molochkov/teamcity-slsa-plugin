package io.github.iaroslavmolochkov.slsa.signing.server;

import java.security.PrivateKey;
import java.security.PublicKey;

/** A parsed server signing key: private key, derived public key, signature algorithm, and DSSE {@code keyId}. */
public record ServerKey(PrivateKey privateKey,
                        PublicKey publicKey,
                        String signatureAlgorithm,
                        String keyId) {
}
