package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

/**
 * The DSSE protocol operations the signers share: producing the bytes that get signed
 * (<a href="https://github.com/secure-systems-lab/dsse/blob/master/protocol.md">PAE</a>) and assembling
 * the signed {@link DsseEnvelope}. A wired bean rather than static helpers, and the one place that
 * touches the package-private {@link Signature}.
 */
@Component
public class Dsse {

    private static final byte SP = ' ';

    /**
     * Pre-Authentication Encoding — the exact bytes signed:
     * <pre>PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body</pre>
     * where SP is a single ASCII space and LEN is the ASCII-decimal byte length.
     */
    @NotNull
    public byte[] pae(@NotNull String payloadType, @NotNull byte[] payload) {
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

    /** Wraps the raw payload bytes and a single raw signature into an envelope, base64-encoding both. */
    @NotNull
    public DsseEnvelope envelope(@NotNull byte[] payloadBytes, @NotNull String keyId, @NotNull byte[] signature) {
        Base64.Encoder b64 = Base64.getEncoder();
        return new DsseEnvelope(
                b64.encodeToString(payloadBytes),
                DsseEnvelope.IN_TOTO_PAYLOAD_TYPE,
                List.of(new Signature(keyId, b64.encodeToString(signature))));
    }

    private static void writeAscii(@NotNull ByteArrayOutputStream out, @NotNull String s) {
        out.writeBytes(s.getBytes(StandardCharsets.US_ASCII));
    }
}
