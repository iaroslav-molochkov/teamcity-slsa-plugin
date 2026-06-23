package io.github.iaroslavmolochkov.teamcity.slsa.persist;

import com.intellij.openapi.diagnostic.Logger;
import jetbrains.buildServer.log.Loggers;
import jetbrains.buildServer.serverSide.SBuild;
import jetbrains.buildServer.serverSide.artifacts.ArtifactsGuard;
import jetbrains.buildServer.serverSide.metadata.MetadataStorage;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;

import java.io.File;
import java.nio.file.Files;
import java.util.Map;

/**
 * Persists the signed attestation: writes the DSSE envelope into the finished build's artifacts as a
 * normal, downloadable artifact ({@code slsa/provenance.intoto.jsonl}) and indexes its metadata so
 * it's queryable via the REST metadata API.
 *
 * <p>The metadata is written directly here via {@link MetadataStorage#addBuildEntry}, using values
 * the caller already has in hand — so there is no dependency on a {@code BuildMetadataProvider}
 * running at the right moment (which would race the asynchronous attestation).
 */
@Component
public class ProvenancePublisher {

    private static final Logger LOG = Loggers.SERVER;

    /** Directory (relative to the build's artifact root) and file name of the attestation. */
    public static final String ARTIFACT_DIR = "slsa";
    public static final String ARTIFACT_NAME = "provenance.intoto.jsonl";
    public static final String ARTIFACT_PATH = ARTIFACT_DIR + "/" + ARTIFACT_NAME;

    /** Metadata provider id under which entries are stored/queried. */
    public static final String METADATA_PROVIDER_ID = "slsa-provenance";

    private final ArtifactsGuard artifactsGuard;
    private final MetadataStorage metadataStorage;

    public ProvenancePublisher(@NotNull ArtifactsGuard artifactsGuard,
                               @NotNull MetadataStorage metadataStorage) {
        this.artifactsGuard = artifactsGuard;
        this.metadataStorage = metadataStorage;
    }

    /**
     * Writes the JSONL bytes as the provenance artifact and, on success, indexes the given metadata.
     * Best-effort: returns {@code false} (and logs) if the artifacts directory is unavailable or the
     * write fails. A metadata-indexing failure is logged but does not fail publishing.
     */
    public boolean publish(@NotNull SBuild build, @NotNull byte[] jsonl, @NotNull Map<String, String> metadata) {
        File artifactsDir;
        try {
            artifactsDir = build.getArtifactsDirectory();
        } catch (Exception e) {
            LOG.warnAndDebugDetails("SLSA: artifacts directory unavailable for build " + build.getBuildId(), e);
            return false;
        }

        File target = new File(new File(artifactsDir, ARTIFACT_DIR), ARTIFACT_NAME);
        artifactsGuard.lockWriting(artifactsDir);
        try {
            Files.createDirectories(target.getParentFile().toPath());
            Files.write(target.toPath(), jsonl);
        } catch (Exception e) {
            LOG.warnAndDebugDetails("SLSA: failed to write provenance artifact for build " + build.getBuildId(), e);
            return false;
        } finally {
            artifactsGuard.unlockWriting(artifactsDir);
        }

        try {
            metadataStorage.addBuildEntry(build.getBuildId(), METADATA_PROVIDER_ID, ARTIFACT_PATH, metadata, true);
        } catch (Exception e) {
            LOG.warnAndDebugDetails("SLSA: failed to index provenance metadata for build " + build.getBuildId(), e);
        }
        return true;
    }
}
