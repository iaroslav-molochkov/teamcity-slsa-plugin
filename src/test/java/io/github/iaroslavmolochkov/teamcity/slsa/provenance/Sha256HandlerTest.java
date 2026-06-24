package io.github.iaroslavmolochkov.teamcity.slsa.provenance;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Sha256HandlerTest {

    @Test
    void digestsEmptyInput() throws IOException {
        assertEquals(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                hexOf(""));
    }

    @Test
    void digestsKnownVector() throws IOException {
        // RFC 6234 / NIST test vector for "abc".
        assertEquals(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                hexOf("abc"));
    }

    @Test
    void streamingAndByteDigestsAgree() throws IOException {
        String input = "x".repeat(100_000);
        assertEquals(hexOf(input), new Sha256Handler().hex(input.getBytes(StandardCharsets.UTF_8)));
        assertTrue(hexOf(input).matches("[0-9a-f]{64}"));
    }

    private static String hexOf(String s) throws IOException {
        return new Sha256Handler().hex(new ByteArrayInputStream(s.getBytes(StandardCharsets.UTF_8)));
    }
}
