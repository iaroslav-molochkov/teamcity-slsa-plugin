package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import com.dynatrace.hash4j.hashing.HashStream128;
import com.dynatrace.hash4j.hashing.HashValue128;
import com.dynatrace.hash4j.hashing.Hasher128;
import com.dynatrace.hash4j.hashing.Hashing;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;

import java.util.UUID;

/** Skeletal {@link ConnectionKeyHandler}: the shared collision-safe hashing scheme; subclasses {@link #funnel} their fields. */
public abstract class AbstractConnectionKeyHandler implements ConnectionKeyHandler {

    private static final Hasher128 HASHER = Hashing.murmur3_128();

    @Override
    public final UUID id(SigningContext context) {
        HashStream128 stream = HASHER.hashStream();
        stream.putString(context.type().value());
        funnel(stream, context);
        HashValue128 hash = stream.get();
        return new UUID(hash.getMostSignificantBits(), hash.getLeastSignificantBits());
    }

    protected abstract void funnel(HashStream128 stream, SigningContext context);

    protected void put(HashStream128 stream, byte tag, String value) {
        stream.putByte(tag);
        if (value == null) {
            stream.putInt(-1);
        } else {
            stream.putString(value);
        }
    }
}
