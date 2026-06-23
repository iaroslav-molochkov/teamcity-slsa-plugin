package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import org.jetbrains.annotations.NotNull;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * DSSE Pre-Authentication Encoding (PAE) — the bytes that actually get signed, per the
 * <a href="https://github.com/secure-systems-lab/dsse/blob/master/protocol.md">DSSE protocol</a>:
 *
 * <pre>PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body</pre>
 *
 * where SP is a single ASCII space and LEN is the ASCII-decimal byte length.
 */
public final class Pae {

    private static final byte SP = ' ';

    private Pae() {
    }

    @NotNull
    public static byte[] encode(@NotNull String payloadType, @NotNull byte[] payload) {
        byte[] typeBytes = payloadType.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeAscii(out, "DSSEv1");
        out.write(SP);
        writeAscii(out, Integer.toString(typeBytes.length));
        out.write(SP);
        out.writeBytes(typeBytes);
        out.write(SP);
        writeAscii(out, Integer.toString(payload.length));
        out.write(SP);
        out.writeBytes(payload);
        return out.toByteArray();
    }

    private static void writeAscii(@NotNull ByteArrayOutputStream out, @NotNull String s) {
        out.writeBytes(s.getBytes(StandardCharsets.US_ASCII));
    }
}
