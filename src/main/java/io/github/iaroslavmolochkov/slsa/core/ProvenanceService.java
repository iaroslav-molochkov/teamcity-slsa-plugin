package io.github.iaroslavmolochkov.slsa.core;

import com.intellij.openapi.diagnostic.Logger;
import io.github.iaroslavmolochkov.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.slsa.persist.ProvenancePublisher;
import io.github.iaroslavmolochkov.slsa.provenance.ArtifactSubject;
import io.github.iaroslavmolochkov.slsa.provenance.ProvenanceBuilder;
import io.github.iaroslavmolochkov.slsa.provenance.ProvenanceJsonHandler;
import io.github.iaroslavmolochkov.slsa.provenance.Sha256Handler;
import io.github.iaroslavmolochkov.slsa.provenance.intoto.InTotoStatement;
import io.github.iaroslavmolochkov.slsa.signing.dsse.DsseEnvelope;
import io.github.iaroslavmolochkov.slsa.signing.sigstore.SigstoreBundleService;
import io.github.iaroslavmolochkov.slsa.signing.SigningService;
import io.github.iaroslavmolochkov.slsa.signing.ParameterValidator;
import io.github.iaroslavmolochkov.slsa.signing.SigningContext;
import jetbrains.buildServer.BuildProblemData;
import jetbrains.buildServer.log.Loggers;
import jetbrains.buildServer.messages.Status;
import jetbrains.buildServer.serverSide.InvalidProperty;
import jetbrains.buildServer.serverSide.SBuildFeatureDescriptor;
import jetbrains.buildServer.serverSide.SRunningBuild;
import jetbrains.buildServer.serverSide.buildLog.MessageAttrs;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/** Orchestrates provenance for a finished build: validate, hash, build, sign, publish. */
@Component
public class ProvenanceService {

    private static final Logger log = Loggers.SERVER;

    private static final String PROBLEM_IDENTITY = "slsaProvenanceConfig";
    private static final String PROBLEM_TYPE = "slsaProvenanceConfig";

    private final ParameterValidator parameterValidator;
    private final ArtifactHasher hasher;
    private final ProvenanceBuilder provenanceBuilder;
    private final ProvenanceJsonHandler provenanceJsonHandler;
    private final SigningService signingService;
    private final SigstoreBundleService sigstoreBundleService;
    private final ProvenancePublisher publisher;
    private final Sha256Handler sha256;

    public ProvenanceService(ParameterValidator parameterValidator,
                             ArtifactHasher hasher,
                             ProvenanceBuilder provenanceBuilder,
                             ProvenanceJsonHandler provenanceJsonHandler,
                             SigningService signingService,
                             SigstoreBundleService sigstoreBundleService,
                             ProvenancePublisher publisher,
                             Sha256Handler sha256) {
        this.parameterValidator = parameterValidator;
        this.hasher = hasher;
        this.provenanceBuilder = provenanceBuilder;
        this.provenanceJsonHandler = provenanceJsonHandler;
        this.signingService = signingService;
        this.sigstoreBundleService = sigstoreBundleService;
        this.publisher = publisher;
        this.sha256 = sha256;
    }

    public void onBuildFinished(SRunningBuild build) {
        if (!build.getBuildStatus().isSuccessful()) {
            log.info("SLSA: build " + build.getBuildId() + " did not succeed; skipping provenance");
            return;
        }

        SBuildFeatureDescriptor feature = build.getBuildFeaturesOfType(SlsaParams.FEATURE_TYPE)
                .stream()
                .findFirst()
                .orElse(null);

        if (feature == null) {
            return;
        }

        SigningContext context = new SigningContext(feature.getParameters());
        List<InvalidProperty> errors = parameterValidator.validate(context);

        if (!errors.isEmpty()) {
            reportError(build, context, errors.stream()
                    .map(InvalidProperty::getInvalidReason)
                    .collect(Collectors.joining("; ")));
            return;
        }

        try {
            sign(build, context);
        } catch (Exception e) {
            log.warnAndDebugDetails("SLSA: signing failed for build " + build.getBuildId(), e);
            reportError(build, context, e.getMessage());
        }
    }

    private void sign(SRunningBuild build, SigningContext context) {
        List<ArtifactSubject> subjects = hasher.hash(build);

        if (subjects.isEmpty()) {
            log.info("SLSA: build " + build.getBuildId() + " has the provenance feature but produced no artifacts");
            return;
        }

        InTotoStatement statement = provenanceBuilder.build(build, subjects, context.includeCustomBuildParameters());

        String builderId = statement.predicate()
                .runDetails()
                .builder()
                .id();

        if (builderId == null || builderId.isBlank()) {
            reportError(build, context, "server root URL is not configured; cannot attest the builder identity");
            return;
        }

        byte[] payload = provenanceJsonHandler.toBytes(statement);
        DsseEnvelope envelope = signingService.sign(context, payload);
        byte[] bundle = provenanceJsonHandler.toBytes(sigstoreBundleService.bundle(envelope));
        String signerId = context.signerType().value();

        if (publisher.publish(build, bundle, metadata(envelope, signerId, bundle))) {
            log.info("SLSA: signed provenance for build " + build.getBuildId() + " ("
                    + subjects.size() + " subject(s)) via '" + signerId + "' signer");
        }
    }

    private void reportError(SRunningBuild build, SigningContext context, String reason) {
        log.warn("SLSA: build " + build.getBuildId() + " - " + reason);

        String message = "SLSA provenance: " + reason;

        if (context.failBuildOnError()) {
            build.addBuildProblem(BuildProblemData.createBuildProblem(PROBLEM_IDENTITY, PROBLEM_TYPE, message));
        } else {
            build.getBuildLog().messageAsync(message, Status.WARNING, MessageAttrs.serverMessage());
        }
    }

    private Map<String, String> metadata(DsseEnvelope envelope, String signerId, byte[] bundle) {
        Map<String, String> metadata = new HashMap<>();

        metadata.put("artifactPath", ProvenancePublisher.ARTIFACT_PATH);
        metadata.put("sha256", sha256.hex(bundle));
        metadata.put("payloadType", envelope.payloadType());
        metadata.put("signer", signerId);
        String keyId = envelope.keyId();

        if (keyId != null) {
            metadata.put("keyId", keyId);
        }

        return metadata;
    }
}
