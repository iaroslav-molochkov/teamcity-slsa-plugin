package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import org.jetbrains.annotations.NotNull;

/**
 * Signing the provenance payload failed at runtime (e.g. the backend rejected the request or a
 * required algorithm is unavailable). Unchecked: the attestation task catches it, logs it, and the
 * build keeps its result — provenance is best-effort, not a gate.
 */
public class SigningException extends RuntimeException {

    public SigningException(@NotNull String message, @NotNull Throwable cause) {
        super(message, cause);
    }

    public SigningException(@NotNull String message) {
        super(message);
    }
}
