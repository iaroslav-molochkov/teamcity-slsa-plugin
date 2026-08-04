package io.github.iaroslavmolochkov.slsa.signing.dsse;

import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

/** Shared DSSE operations: PAE encoding and {@link DsseEnvelope} assembly. */
@Component
public class DsseService {

    private static final byte SP = ' ';
    private static final Base64.Encoder encoder = Base64.getEncoder();

    public byte[] pae(String payloadType, byte[] payload) {
        byte[] typeBytes = payloadType.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        writeText(out, "DSSEv1");
        out.write(SP);
        writeText(out, Integer.toString(typeBytes.length));
        out.write(SP);
        out.writeBytes(typeBytes);
        out.write(SP);
        writeText(out, Integer.toString(payload.length));
        out.write(SP);
        out.writeBytes(payload);

        return out.toByteArray();
    }

    public DsseEnvelope envelope(byte[] payloadBytes, String keyId, byte[] signature) {
        return new DsseEnvelope(
                encoder.encodeToString(payloadBytes),
                DsseEnvelope.IN_TOTO_PAYLOAD_TYPE,
                List.of(new DsseSignature(keyId, encoder.encodeToString(signature))));
    }

    private void writeText(ByteArrayOutputStream out, String s) {
        out.writeBytes(s.getBytes(StandardCharsets.UTF_8));
    }
}
