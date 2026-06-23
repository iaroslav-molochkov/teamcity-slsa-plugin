package io.github.iaroslavmolochkov.teamcity.slsa.run;

import com.intellij.openapi.diagnostic.Logger;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SignerConfig;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.persist.ProvenancePublisher;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.ArtifactSubject;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.ProvenanceBuilder;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.ProvenanceJson;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.Sha256;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.intoto.InTotoStatement;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.ConfigMappers;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.ConfigResult;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.DsseEnvelope;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.Signer;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerFactories;
import jetbrains.buildServer.BuildProblemData;
import jetbrains.buildServer.log.Loggers;
import jetbrains.buildServer.serverSide.BuildServerAdapter;
import jetbrains.buildServer.serverSide.BuildServerListener;
import jetbrains.buildServer.serverSide.InvalidProperty;
import jetbrains.buildServer.serverSide.SBuild;
import jetbrains.buildServer.serverSide.SBuildFeatureDescriptor;
import jetbrains.buildServer.serverSide.TeamCityProperties;
import jetbrains.buildServer.util.EventDispatcher;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.stream.Collectors;

/**
 * Orchestrates provenance for a finished build. Mapping params into a validated, typed config runs
 * synchronously on the build-finishing thread so an invalid config is reported as a <em>build
 * problem</em> — the only validation point DSL/REST-created configs ever hit. The heavy work
 * (hashing, building the signer, signing, publishing) is scheduled on a pool so finishing isn't
 * blocked, and runs against an already-valid config.
 */
@Component
public class ProvenanceService {

    private static final Logger LOG = Loggers.SERVER;

    /** Server property to override the attestation pool size. */
    public static final String ATTEST_THREADS_PROPERTY = "teamcity.slsa.attestThreads";

    private static final String PROBLEM_IDENTITY = "slsaProvenanceConfig";
    private static final String PROBLEM_TYPE = "slsaProvenanceConfig";

    private final ArtifactHasher hasher;
    private final ProvenanceBuilder provenanceBuilder;
    private final ConfigMappers configMappers;
    private final SignerFactories signerFactories;
    private final ProvenancePublisher publisher;
    private final ExecutorService pool;

    public ProvenanceService(@NotNull EventDispatcher<BuildServerListener> eventDispatcher,
                             @NotNull ArtifactHasher hasher,
                             @NotNull ProvenanceBuilder provenanceBuilder,
                             @NotNull ConfigMappers configMappers,
                             @NotNull SignerFactories signerFactories,
                             @NotNull ProvenancePublisher publisher) {
        this.hasher = hasher;
        this.provenanceBuilder = provenanceBuilder;
        this.configMappers = configMappers;
        this.signerFactories = signerFactories;
        this.publisher = publisher;

        int threads = TeamCityProperties.getInteger(ATTEST_THREADS_PROPERTY, SlsaExecutors.defaultPoolSize());
        pool = SlsaExecutors.fixedDaemonPool(threads, "slsa-attest");
        eventDispatcher.addListener(new BuildServerAdapter() {
            @Override
            public void serverShutdown() {
                pool.shutdownNow();
            }
        });
    }

    /**
     * Called on the build-finishing thread. Maps the (at most one) provenance feature's params into a
     * validated config and — if valid — schedules signing; otherwise records a build problem.
     */
    public void onBuildFinished(@NotNull SBuild build) {
        SBuildFeatureDescriptor feature = build.getBuildFeaturesOfType(SlsaParams.FEATURE_TYPE)
                .stream()
                .findFirst()
                .orElse(null);

        if (feature == null) {
            return;
        }

        ConfigResult<SignerConfig> result = configMappers.map(feature.getParameters());

        if (!result.isValid()) {
            reportProblem(build, result.errors());
            return;
        }

        SignerConfig config = result.config();
        pool.execute(() -> {
            try {
                sign(build, config);
            } catch (Throwable t) {
                LOG.warnAndDebugDetails("SLSA: attestation task failed for build " + build.getBuildId(), t);
            }
        });
    }

    private void sign(@NotNull SBuild build, @NotNull SignerConfig config) {
        List<ArtifactSubject> subjects = hasher.hash(build);

        if (subjects.isEmpty()) {
            LOG.info("SLSA: build " + build.getBuildId() + " has the provenance feature but produced no artifacts");
            return;
        }

        InTotoStatement statement = provenanceBuilder.build(build, subjects);
        byte[] payload = ProvenanceJson.toBytes(statement);

        Signer signer = signerFactories.create(config);
        DsseEnvelope envelope = signer.sign(payload);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(ProvenanceJson.toBytes(envelope));
        out.write('\n');
        byte[] jsonl = out.toByteArray();

        if (publisher.publish(build, jsonl, metadata(envelope, config.signerId(), jsonl))) {
            //todo debug it, many arts, no point in spam
            LOG.info("SLSA: signed provenance for build " + build.getBuildId() + " ("
                    + subjects.size() + " subject(s)) via '" + config.signerId() + "' signer");
        }
    }

    /** Records a build problem (visible on the build) and logs it. */
    private void reportProblem(@NotNull SBuild build, @NotNull List<InvalidProperty> errors) {
        String reason = errors.stream()
                .map(InvalidProperty::getInvalidReason)
                .collect(Collectors.joining("; "));
        LOG.warn("SLSA: build " + build.getBuildId() + " — " + reason);

        build.addBuildProblem(BuildProblemData.createBuildProblem(PROBLEM_IDENTITY, PROBLEM_TYPE, "SLSA provenance: " + reason));
    }

    /** Indexable metadata for the attestation, computed from values already in hand (no re-read). */
    @NotNull
    private Map<String, String> metadata(@NotNull DsseEnvelope envelope, @NotNull String signerId, @NotNull byte[] jsonl) {
        Map<String, String> metadata = new HashMap<>();
        metadata.put("artifactPath", ProvenancePublisher.ARTIFACT_PATH);
        metadata.put("sha256", Sha256.hex(jsonl));
        metadata.put("payloadType", envelope.payloadType());
        metadata.put("signer", signerId);
        String keyId = envelope.keyId();

        if (keyId != null) {
            metadata.put("keyId", keyId);
        }

        return metadata;
    }
}
