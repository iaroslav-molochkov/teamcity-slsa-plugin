package io.github.iaroslavmolochkov.slsa.provenance;

import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/** Computes SHA-256 digests. */
@Component
public class Sha256Handler {

    private static final int BUFFER_SIZE = 64 * 1024;
    private static final HexFormat hexFormat = HexFormat.of();

    public String hex(InputStream in) throws IOException {
        MessageDigest digest = newDigest();
        byte[] buffer = new byte[BUFFER_SIZE];
        int read;

        while ((read = in.read(buffer)) != -1) {
            digest.update(buffer, 0, read);
        }

        return toHex(digest.digest());
    }

    public String hex(byte[] bytes) {
        return toHex(newDigest().digest(bytes));
    }

    private MessageDigest newDigest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private String toHex(byte[] bytes) {
        return hexFormat.formatHex(bytes);
    }
}
