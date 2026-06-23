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
 * The entry point: reads the {@link SignerType} from the params and hands them to the matching
 * {@link SignerProcessor} bean (looked up in a map, no branching on type). {@link #validate} backs the
 * UI parameters processor; {@link #process} is the build-time path. Selecting an absent or unknown
 * signer is itself a validation error.
 */
@Component
public class SignerHandler {

    private final Map<SignerType, SignerProcessor> processors = new EnumMap<>(SignerType.class);

    public SignerHandler(@NotNull List<SignerProcessor> processors) {
        for (SignerProcessor processor : processors) {
            this.processors.put(processor.type(), processor);
        }
    }

    /** Validation errors for the params (empty when valid), including signer selection. For the UI. */
    @NotNull
    public List<InvalidProperty> validate(@NotNull Map<String, String> params) {
        SignerProcessor processor = processors.get(signerType(params));
        return processor == null ? selectionError(params) : processor.validate(params);
    }

    /** Builds a ready {@link Signer} from the params, or returns the validation errors. For the runtime. */
    @NotNull
    public Result<Signer> process(@NotNull Map<String, String> params) {
        SignerProcessor processor = processors.get(signerType(params));
        return processor == null ? Result.invalid(selectionError(params)) : processor.process(params);
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
