package io.github.iaroslavmolochkov.teamcity.slsa.persist;

import com.intellij.openapi.diagnostic.Logger;
import jetbrains.buildServer.log.Loggers;
import jetbrains.buildServer.serverSide.SBuild;
import jetbrains.buildServer.serverSide.artifacts.ArtifactsGuard;
import jetbrains.buildServer.serverSide.metadata.MetadataStorage;
import org.springframework.stereotype.Component;

import java.io.File;
import java.nio.file.Files;
import java.util.Map;

/** Writes the signed envelope as the {@code provenance.intoto.jsonl} build artifact and indexes its metadata. */
@Component
public class ProvenancePublisher {

    private static final Logger log = Loggers.SERVER;

    /** File name (and artifact path, relative to the build's artifact root) of the attestation. */
    public static final String ARTIFACT_NAME = "provenance.intoto.jsonl";
    public static final String ARTIFACT_PATH = ARTIFACT_NAME;

    /** Metadata provider id under which entries are stored/queried. */
    public static final String METADATA_PROVIDER_ID = "slsa-provenance";

    private final ArtifactsGuard artifactsGuard;
    private final MetadataStorage metadataStorage;

    public ProvenancePublisher(ArtifactsGuard artifactsGuard,
                               MetadataStorage metadataStorage) {
        this.artifactsGuard = artifactsGuard;
        this.metadataStorage = metadataStorage;
    }

    /**
     * Writes the JSONL bytes as the provenance artifact and, on success, indexes the given metadata.
     * Best-effort: returns {@code false} (and logs) if the artifacts directory is unavailable or the
     * write fails. A metadata-indexing failure is logged but does not fail publishing.
     */
    public boolean publish(SBuild build, byte[] jsonl, Map<String, String> metadata) {
        File artifactsDir;
        try {
            artifactsDir = build.getArtifactsDirectory();
        } catch (Exception e) {
            log.warnAndDebugDetails("SLSA: artifacts directory unavailable for build " + build.getBuildId(), e);
            return false;
        }

        File target = new File(artifactsDir, ARTIFACT_NAME);
        artifactsGuard.lockWriting(artifactsDir);
        try {
            Files.createDirectories(artifactsDir.toPath());
            Files.write(target.toPath(), jsonl);
        } catch (Exception e) {
            log.warnAndDebugDetails("SLSA: failed to write provenance artifact for build " + build.getBuildId(), e);
            return false;
        } finally {
            artifactsGuard.unlockWriting(artifactsDir);
        }

        try {
            metadataStorage.addBuildEntry(build.getBuildId(), METADATA_PROVIDER_ID, ARTIFACT_PATH, metadata, true);
        } catch (Exception e) {
            log.warnAndDebugDetails("SLSA: failed to index provenance metadata for build " + build.getBuildId(), e);
        }
        return true;
    }
}
