package io.github.iaroslavmolochkov.slsa.persist;

import com.intellij.openapi.diagnostic.Logger;
import jetbrains.buildServer.log.Loggers;
import jetbrains.buildServer.serverSide.SBuild;
import jetbrains.buildServer.serverSide.artifacts.ArtifactsGuard;
import jetbrains.buildServer.serverSide.metadata.MetadataStorage;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Map;

/**
 * Writes the signed envelope as the {@code provenance.sigstore.json} build
 * artifact (a Sigstore bundle, verifiable
 * with {@code cosign verify-blob-attestation}) and indexes its metadata.
 */
@Component
public class ProvenancePublisher {

    private static final Logger log = Loggers.SERVER;

    public static final String ARTIFACT_NAME = "provenance.sigstore.json";
    public static final String ARTIFACT_PATH = ARTIFACT_NAME;

    public static final String METADATA_PROVIDER_ID = "slsa-provenance";

    private final ArtifactsGuard artifactsGuard;
    private final MetadataStorage metadataStorage;

    public ProvenancePublisher(ArtifactsGuard artifactsGuard,
            MetadataStorage metadataStorage) {
        this.artifactsGuard = artifactsGuard;
        this.metadataStorage = metadataStorage;
    }

    public void publish(SBuild build, byte[] bundle, Map<String, String> metadata) {
        File artifactsDir;

        try {
            artifactsDir = build.getArtifactsDirectory();
        } catch (Exception e) {
            throw new ProvenancePublishingException("Artifacts directory unavailable for build " + build.getBuildId(),
                    e);
        }

        artifactsGuard.lockWriting(artifactsDir);

        Path dir = artifactsDir.toPath();
        Path filePath = artifactsDir.toPath().resolve(ARTIFACT_NAME);
        Path tempPath = null;

        try {
            Files.createDirectories(dir);
            tempPath = Files.createTempFile(dir, ARTIFACT_NAME, null);
            Files.write(tempPath, bundle);
            Files.move(tempPath, filePath, StandardCopyOption.ATOMIC_MOVE);
        } catch (Exception e) {
            RuntimeException t = new ProvenancePublishingException(
                    "Failed to write provenance artifact for build " + build.getBuildId(), e);

            if (tempPath != null) {
                try {
                    Files.deleteIfExists(tempPath);
                } catch (IOException ex) {
                    t.addSuppressed(ex);
                    log.warnAndDebugDetails("SLSA: failed to clean up the provenance file", ex);
                }
            }

            throw t;
        } finally {
            artifactsGuard.unlockWriting(artifactsDir);
        }

        try {
            metadataStorage.addBuildEntry(build.getBuildId(), METADATA_PROVIDER_ID, ARTIFACT_PATH, metadata, true);
        } catch (Exception e) {
            log.warnAndDebugDetails("SLSA: failed to index provenance metadata for build " + build.getBuildId(), e);
        }
    }
}
