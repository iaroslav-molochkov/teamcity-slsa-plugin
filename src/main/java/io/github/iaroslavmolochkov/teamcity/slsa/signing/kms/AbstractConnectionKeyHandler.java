package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import com.dynatrace.hash4j.hashing.HashStream128;
import com.dynatrace.hash4j.hashing.HashValue128;
import com.dynatrace.hash4j.hashing.Hasher128;
import com.dynatrace.hash4j.hashing.Hashing;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;

import java.util.UUID;

/** Skeletal {@link ConnectionKeyHandler}: the shared hashing scheme over region and the assumed role; subclasses {@link #funnel} their base-specific fields. */
public abstract class AbstractConnectionKeyHandler implements ConnectionKeyHandler {

    private static final Hasher128 HASHER = Hashing.murmur3_128();

    private static final byte REGION = 1;
    private static final byte ASSUME_ROLE = 2;
    private static final byte ROLE_ARN = 3;
    private static final byte EXTERNAL_ID = 4;
    private static final byte STS_ENDPOINT = 5;

    @Override
    public final UUID id(SigningContext context) {
        HashStream128 stream = HASHER.hashStream();
        stream.putString(context.type().value());
        funnelCommon(stream, context);
        funnel(stream, context);
        HashValue128 hash = stream.get();
        return new UUID(hash.getMostSignificantBits(), hash.getLeastSignificantBits());
    }

    private void funnelCommon(HashStream128 stream, SigningContext context) {
        put(stream, REGION, context.get(SlsaParams.REGION));
        stream.putByte(ASSUME_ROLE);
        stream.putBoolean(context.assumeRole());
        if (context.assumeRole()) {
            put(stream, ROLE_ARN, context.get(SlsaParams.ASSUME_ROLE_ARN));
            put(stream, EXTERNAL_ID, context.get(SlsaParams.ASSUME_ROLE_EXTERNAL_ID));
            put(stream, STS_ENDPOINT, context.get(SlsaParams.STS_ENDPOINT));
        }
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
