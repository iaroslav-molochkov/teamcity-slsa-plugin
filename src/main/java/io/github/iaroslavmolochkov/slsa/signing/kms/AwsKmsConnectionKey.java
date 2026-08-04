package io.github.iaroslavmolochkov.slsa.signing.kms;

import com.dynatrace.hash4j.hashing.HashStream128;
import com.dynatrace.hash4j.hashing.HashValue128;
import com.dynatrace.hash4j.hashing.Hasher128;
import com.dynatrace.hash4j.hashing.Hashing;
import io.github.iaroslavmolochkov.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.slsa.signing.CredentialsType;
import io.github.iaroslavmolochkov.slsa.signing.SigningContext;
import org.springframework.stereotype.Component;

import java.util.UUID;

/** Derives a connection's stable KMS-client-cache id from the credentials, region, and any assumed role. */
@Component
public class AwsKmsConnectionKey {

    private static final Hasher128 HASHER = Hashing.murmur3_128();

    private static final byte REGION = 1;
    private static final byte ASSUME_ROLE = 2;
    private static final byte ROLE_ARN = 3;
    private static final byte EXTERNAL_ID = 4;
    private static final byte STS_ENDPOINT = 5;
    private static final byte CREDENTIALS = 6;
    private static final byte ACCESS_KEY_ID = 7;
    private static final byte SECRET = 8;

    public UUID id(SigningContext context) {
        HashStream128 stream = HASHER.hashStream();
        stream.putString(context.signerType().value());

        put(stream, REGION, context.get(SlsaParams.REGION));

        CredentialsType source = context.credentialsType();
        put(stream, CREDENTIALS, source == null ? null : source.value());

        if (source == CredentialsType.STATIC_CREDENTIALS) {
            put(stream, ACCESS_KEY_ID, context.get(SlsaParams.ACCESS_KEY_ID));
            put(stream, SECRET, context.get(SlsaParams.SECRET_ACCESS_KEY));
        }

        stream.putByte(ASSUME_ROLE);
        stream.putBoolean(context.assumeRole());

        if (context.assumeRole()) {
            put(stream, ROLE_ARN, context.get(SlsaParams.ASSUME_ROLE_ARN));
            put(stream, EXTERNAL_ID, context.get(SlsaParams.ASSUME_ROLE_EXTERNAL_ID));
            put(stream, STS_ENDPOINT, context.get(SlsaParams.STS_ENDPOINT));
        }

        HashValue128 hash = stream.get();
        return new UUID(hash.getMostSignificantBits(), hash.getLeastSignificantBits());
    }

    private void put(HashStream128 stream, byte tag, String value) {
        stream.putByte(tag);

        if (value == null) {
            stream.putInt(-1);
        } else {
            stream.putString(value);
        }
    }
}
