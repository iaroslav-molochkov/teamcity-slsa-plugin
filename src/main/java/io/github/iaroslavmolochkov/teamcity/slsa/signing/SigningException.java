package io.github.iaroslavmolochkov.teamcity.slsa.signing;


public class SigningException extends RuntimeException {

    public SigningException(String message, Throwable cause) {
        super(message, cause);
    }

    public SigningException(String message) {
        super(message);
    }
}
