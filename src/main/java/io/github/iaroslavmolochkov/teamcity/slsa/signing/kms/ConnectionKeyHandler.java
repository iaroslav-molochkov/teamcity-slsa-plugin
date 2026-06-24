package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import com.dynatrace.hash4j.hashing.HashStream128;
import com.dynatrace.hash4j.hashing.HashValue128;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;

import java.util.UUID;

/**
 * Produces the stable id (client-cache key) for one connection type. Each handler is self-contained:
 * it creates a fresh hash stream (from its own immutable {@code Hashing.murmur3_128()} constant), feeds
 * the type discriminator and its own fields, and returns the id. The only shared bits are the two
 * mechanical helpers below — {@link #put} (length-framed, null-safe) and {@link #digest} (finalize) —
 * so the framing/collision-safety is defined once. Selected by {@link #type()}.
 */
public interface ConnectionKeyHandler {

    SignerType type();

    String id(SigningContext context);

    /** Adds one tagged field; a {@code null} value is recorded as absent (distinct from empty). */
    static void put(HashStream128 stream, byte tag, String value) {
        stream.putByte(tag);
        if (value == null) {
            stream.putInt(-1);
        } else {
            stream.putString(value);
        }
    }

    /** Finalizes the stream to a stable id string. */
    static String digest(HashStream128 stream) {
        HashValue128 hash = stream.get();
        return new UUID(hash.getMostSignificantBits(), hash.getLeastSignificantBits()).toString();
    }
}
