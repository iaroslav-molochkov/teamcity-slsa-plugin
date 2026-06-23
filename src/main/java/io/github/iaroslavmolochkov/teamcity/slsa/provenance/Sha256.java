package io.github.iaroslavmolochkov.teamcity.slsa.provenance;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Computes SHA-256 digests. SLSA provenance identifies each subject (artifact)
 * by its content digest, so this is the core hashing primitive of the plugin.
 */
public final class Sha256 {

    // 64 KiB keeps syscall overhead low when streaming multi-GB artifacts.
    private static final int BUFFER_SIZE = 64 * 1024;

    private Sha256() {
    }

    /**
     * Streams the given input and returns its SHA-256 digest as a lowercase hex string.
     * The caller is responsible for closing the stream.
     */
    public static String hex(InputStream in) throws IOException {
        MessageDigest digest = newDigest();
        byte[] buffer = new byte[BUFFER_SIZE];
        int read;
        while ((read = in.read(buffer)) != -1) {
            digest.update(buffer, 0, read);
        }
        return toHex(digest.digest());
    }

    /** Returns the SHA-256 digest of the given bytes as a lowercase hex string. */
    public static String hex(byte[] bytes) {
        return toHex(newDigest().digest(bytes));
    }

    private static MessageDigest newDigest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed to be available on every JVM.
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}
