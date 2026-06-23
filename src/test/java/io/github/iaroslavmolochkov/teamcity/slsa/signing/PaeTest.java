package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class PaeTest {

    @Test
    void matchesDsseSpecExample() {
        byte[] pae = Pae.encode("http://example.com/HelloWorld",
                "hello world".getBytes(StandardCharsets.UTF_8));
        assertEquals("DSSEv1 29 http://example.com/HelloWorld 11 hello world",
                new String(pae, StandardCharsets.UTF_8));
    }

    @Test
    void usesByteLengthNotCharLength() {
        // "héllo" is 6 UTF-8 bytes (é = 2 bytes) but 5 chars; PAE must use the byte length.
        byte[] payload = "héllo".getBytes(StandardCharsets.UTF_8);
        byte[] pae = Pae.encode("t", payload);
        assertEquals("DSSEv1 1 t 6 héllo", new String(pae, StandardCharsets.UTF_8));
    }

    @Test
    void embedsRawPayloadBytes() {
        byte[] payload = {0, 1, 2, 3};
        byte[] pae = Pae.encode("application/vnd.in-toto+json", payload);
        byte[] prefix = "DSSEv1 28 application/vnd.in-toto+json 4 ".getBytes(StandardCharsets.US_ASCII);
        byte[] tail = new byte[4];
        System.arraycopy(pae, pae.length - 4, tail, 0, 4);
        assertArrayEquals(payload, tail);
        byte[] head = new byte[prefix.length];
        System.arraycopy(pae, 0, head, 0, prefix.length);
        assertArrayEquals(prefix, head);
    }
}
