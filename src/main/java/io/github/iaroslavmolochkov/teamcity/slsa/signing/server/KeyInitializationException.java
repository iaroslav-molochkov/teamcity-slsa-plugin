package io.github.iaroslavmolochkov.teamcity.slsa.signing.server;

import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningException;

/** The signer's key material could not be loaded or generated (a setup failure, before any signing). */
public class KeyInitializationException extends SigningException {

    public KeyInitializationException(String message, Throwable cause) {
        super(message, cause);
    }
}
