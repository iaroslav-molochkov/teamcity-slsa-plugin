package io.github.iaroslavmolochkov.teamcity.slsa.core;

import com.intellij.openapi.diagnostic.Logger;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.persist.ProvenancePublisher;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.ArtifactSubject;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.ProvenanceBuilder;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.ProvenanceJsonHandler;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.Sha256Handler;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.intoto.InTotoStatement;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.DsseEnvelope;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningServices;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.Validators;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import jetbrains.buildServer.BuildProblemData;
import jetbrains.buildServer.log.Loggers;
import jetbrains.buildServer.serverSide.InvalidProperty;
import jetbrains.buildServer.serverSide.SBuild;
import jetbrains.buildServer.serverSide.SBuildFeatureDescriptor;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Orchestrates provenance for a finished build, synchronously on the build-finishing thread: validate
 * by type → hash the artifacts → build the statement → hand the payload to the signing service for the
 * type → attach the result. Any failure — an invalid config or a signing error — is reported as a
 * <em>build problem</em> right there, so it is visible on the build (and never silently swallowed).
 *
 * <p>The client is never built until there is a payload to sign, so a build with no artifacts touches
 * no AWS at all.
 */
@Component
public class ProvenanceService {

    private static final Logger log = Loggers.SERVER;

    private static final String PROBLEM_IDENTITY = "slsaProvenanceConfig";
    private static final String PROBLEM_TYPE = "slsaProvenanceConfig";

    private final Validators validators;
    private final ArtifactHasher hasher;
    private final ProvenanceBuilder provenanceBuilder;
    private final ProvenanceJsonHandler provenanceJsonHandler;
    private final SigningServices signingServices;
    private final ProvenancePublisher publisher;
    private final Sha256Handler sha256;

    public ProvenanceService(Validators validators,
                             ArtifactHasher hasher,
                             ProvenanceBuilder provenanceBuilder,
                             ProvenanceJsonHandler provenanceJsonHandler,
                             SigningServices signingServices,
                             ProvenancePublisher publisher,
                             Sha256Handler sha256) {
        this.validators = validators;
        this.hasher = hasher;
        this.provenanceBuilder = provenanceBuilder;
        this.provenanceJsonHandler = provenanceJsonHandler;
        this.signingServices = signingServices;
        this.publisher = publisher;
        this.sha256 = sha256;
    }

    /**
     * Called on the build-finishing thread. Validates the (at most one) provenance feature's params,
     * hashes, signs, and publishes; an invalid config or a signing failure is recorded as a build problem.
     */
    public void onBuildFinished(SBuild build) {
        SBuildFeatureDescriptor feature = build.getBuildFeaturesOfType(SlsaParams.FEATURE_TYPE)
                .stream()
                .findFirst()
                .orElse(null);

        if (feature == null) {
            return;
        }

        SigningContext context = new SigningContext(feature.getParameters());
        List<InvalidProperty> errors = validators.validate(context);

        if (!errors.isEmpty()) {
            reportProblem(build, errors.stream()
                    .map(InvalidProperty::getInvalidReason)
                    .collect(Collectors.joining("; ")));
            return;
        }

        try {
            sign(build, context);
        } catch (Exception e) {
            log.warnAndDebugDetails("SLSA: signing failed for build " + build.getBuildId(), e);
            reportProblem(build, e.getMessage());
        }
    }

    private void sign(SBuild build, SigningContext context) {
        List<ArtifactSubject> subjects = hasher.hash(build);

        if (subjects.isEmpty()) {
            log.info("SLSA: build " + build.getBuildId() + " has the provenance feature but produced no artifacts");
            return;
        }

        InTotoStatement statement = provenanceBuilder.build(build, subjects);
        byte[] payload = provenanceJsonHandler.toBytes(statement);

        DsseEnvelope envelope = signingServices.sign(context, payload);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(provenanceJsonHandler.toBytes(envelope));
        out.write('\n');
        byte[] jsonl = out.toByteArray();

        String signerId = context.type().value();
        if (publisher.publish(build, jsonl, metadata(envelope, signerId, jsonl))) {
            log.info("SLSA: signed provenance for build " + build.getBuildId() + " ("
                    + subjects.size() + " subject(s)) via '" + signerId + "' signer");
        }
    }

    /** Records a build problem (visible on the build) and logs it. */
    private void reportProblem(SBuild build, String reason) {
        log.warn("SLSA: build " + build.getBuildId() + " — " + reason);
        build.addBuildProblem(BuildProblemData.createBuildProblem(PROBLEM_IDENTITY, PROBLEM_TYPE, "SLSA provenance: " + reason));
    }

    /** Indexable metadata for the attestation, computed from values already in hand (no re-read). */
    private Map<String, String> metadata(DsseEnvelope envelope, String signerId, byte[] jsonl) {
        Map<String, String> metadata = new HashMap<>();
        metadata.put("artifactPath", ProvenancePublisher.ARTIFACT_PATH);
        metadata.put("sha256", sha256.hex(jsonl));
        metadata.put("payloadType", envelope.payloadType());
        metadata.put("signer", signerId);
        String keyId = envelope.keyId();

        if (keyId != null) {
            metadata.put("keyId", keyId);
        }

        return metadata;
    }
}
