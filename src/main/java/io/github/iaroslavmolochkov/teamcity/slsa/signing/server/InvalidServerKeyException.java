package io.github.iaroslavmolochkov.teamcity.slsa.signing.server;

import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningException;

/**
 * The configured server signing key cannot be used: it is missing, not a supported PEM key, of an
 * unsupported algorithm, or its public key could not be derived. Surfaced at configuration time (as a
 * validation error) and, as a last resort, at signing time.
 */
public class InvalidServerKeyException extends SigningException {

    public InvalidServerKeyException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidServerKeyException(String message) {
        super(message);
    }
}
