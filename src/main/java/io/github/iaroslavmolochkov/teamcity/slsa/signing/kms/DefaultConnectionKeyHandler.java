package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import com.dynatrace.hash4j.hashing.HashStream128;
import com.dynatrace.hash4j.hashing.Hasher128;
import com.dynatrace.hash4j.hashing.Hashing;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import org.springframework.stereotype.Component;

/** Default-provider-chain connections are identified by region alone (creds come from the environment). */
@Component
public class DefaultConnectionKeyHandler implements ConnectionKeyHandler {

    private static final Hasher128 HASHER = Hashing.murmur3_128();

    private static final byte REGION = 1;

    @Override
    public SignerType type() {
        return SignerType.AWS_KMS_DEFAULT;
    }

    @Override
    public String id(SigningContext context) {
        HashStream128 stream = HASHER.hashStream();
        stream.putString(context.type().value());
        ConnectionKeyHandler.put(stream, REGION, context.get(SlsaParams.REGION));
        return ConnectionKeyHandler.digest(stream);
    }
}
