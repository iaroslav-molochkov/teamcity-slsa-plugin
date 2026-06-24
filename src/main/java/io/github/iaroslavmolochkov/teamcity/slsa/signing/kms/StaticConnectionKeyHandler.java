package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import com.dynatrace.hash4j.hashing.HashStream128;
import com.dynatrace.hash4j.hashing.Hasher128;
import com.dynatrace.hash4j.hashing.Hashing;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;

/**
 * Static-keys connections are identified by region + access key id + secret. The stored (scrambled)
 * secret is used as-is: it's deterministic, so the same secret keys the same client, and distinct
 * secrets never collide — no need to unscramble just to derive an identity.
 */
@Component
public class StaticConnectionKeyHandler implements ConnectionKeyHandler {

    private static final Hasher128 HASHER = Hashing.murmur3_128();

    private static final byte REGION = 1;
    private static final byte ACCESS_KEY_ID = 2;
    private static final byte SECRET = 3;

    @NotNull
    @Override
    public SignerType type() {
        return SignerType.AWS_KMS_STATIC;
    }

    @NotNull
    @Override
    public String id(@NotNull SigningContext context) {
        HashStream128 stream = HASHER.hashStream();
        stream.putString(context.type().value());
        ConnectionKeyHandler.put(stream, REGION, context.get(SlsaParams.REGION));
        ConnectionKeyHandler.put(stream, ACCESS_KEY_ID, context.get(SlsaParams.ACCESS_KEY_ID));
        ConnectionKeyHandler.put(stream, SECRET, context.get(SlsaParams.SECRET_ACCESS_KEY));
        return ConnectionKeyHandler.digest(stream);
    }
}
