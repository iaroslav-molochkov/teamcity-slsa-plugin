package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import org.jetbrains.annotations.NotNull;

/** The signer's key material could not be loaded or generated (a setup failure, before any signing). */
public class KeyInitializationException extends SigningException {

    public KeyInitializationException(@NotNull String message, @NotNull Throwable cause) {
        super(message, cause);
    }
}
