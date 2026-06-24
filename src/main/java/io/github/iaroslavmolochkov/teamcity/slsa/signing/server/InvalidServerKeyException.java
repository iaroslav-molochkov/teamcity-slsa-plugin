package io.github.iaroslavmolochkov.teamcity.slsa.signing.server;

import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningException;

public class InvalidServerKeyException extends SigningException {

    public InvalidServerKeyException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidServerKeyException(String message) {
        super(message);
    }
}
