package io.github.iaroslavmolochkov.teamcity.slsa.signing.server;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * A parsed server signing key: the private key to sign with, the public key derived from it (so the
 * {@code keyId} can be computed without the user supplying it separately), the JCA signature algorithm
 * matching the key, and the default DSSE {@code keyId} ({@code sha256:<pubkey>}).
 */
public record ServerKey(PrivateKey privateKey, PublicKey publicKey, String signatureAlgorithm, String keyId) {
}
