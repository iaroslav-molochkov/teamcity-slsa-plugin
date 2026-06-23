package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.util.Params;
import jetbrains.buildServer.serverSide.InvalidProperty;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.springframework.stereotype.Component;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * The entry point: reads the {@link SignerType} from the params and hands the params to the matching
 * {@link SignerResolver}. {@link #validate} backs the UI parameters processor; {@link #resolve} is the
 * build-time path. Selecting an absent or unknown signer is itself a validation error.
 */
@Component
public class SignerHandler {

    private final Map<SignerType, SignerResolver> resolvers = new EnumMap<>(SignerType.class);

    public SignerHandler(@NotNull List<SignerResolver> resolvers) {
        for (SignerResolver resolver : resolvers) {
            this.resolvers.put(resolver.type(), resolver);
        }
    }

    /** Validation errors for the params (empty when valid), including signer selection. For the UI. */
    @NotNull
    public List<InvalidProperty> validate(@NotNull Map<String, String> params) {
        SignerResolver resolver = resolvers.get(signerType(params));
        return resolver == null ? selectionError(params) : resolver.validate(params);
    }

    /** Resolves the params into a ready {@link Signer}, or the validation errors. For the runtime. */
    @NotNull
    public Result<Signer> resolve(@NotNull Map<String, String> params) {
        SignerResolver resolver = resolvers.get(signerType(params));
        return resolver == null ? Result.invalid(selectionError(params)) : resolver.resolve(params);
    }

    @Nullable
    private static SignerType signerType(@NotNull Map<String, String> params) {
        return SignerType.fromValue(Params.get(params, SlsaParams.SIGNER));
    }

    @NotNull
    private static List<InvalidProperty> selectionError(@NotNull Map<String, String> params) {
        String raw = Params.get(params, SlsaParams.SIGNER);
        return List.of(new InvalidProperty(SlsaParams.SIGNER,
                raw == null ? "A signer must be selected" : "Unknown signer: " + raw));
    }
}
