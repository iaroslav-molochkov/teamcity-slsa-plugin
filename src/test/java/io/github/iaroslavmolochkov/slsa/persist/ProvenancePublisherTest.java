package io.github.iaroslavmolochkov.slsa.persist;

import jetbrains.buildServer.serverSide.SBuild;
import jetbrains.buildServer.serverSide.artifacts.ArtifactsGuard;
import jetbrains.buildServer.serverSide.metadata.MetadataStorage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.InOrder;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ProvenancePublisherTest {

    private static final long BUILD_ID = 42L;
    private static final byte[] BUNDLE = "signed bundle".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    private static final Map<String, String> METADATA = Map.of("sha256", "abc123");

    private final ArtifactsGuard artifactsGuard = mock(ArtifactsGuard.class);
    private final MetadataStorage metadataStorage = mock(MetadataStorage.class);
    private final ProvenancePublisher publisher = new ProvenancePublisher(artifactsGuard, metadataStorage);

    @Test
    void publishesCompletedArtifactWithoutLeavingTemporaryFiles(@TempDir Path artifactsDir) throws Exception {
        SBuild build = build(artifactsDir);

        publisher.publish(build, BUNDLE, METADATA);

        assertArrayEquals(BUNDLE, Files.readAllBytes(artifactsDir.resolve(ProvenancePublisher.ARTIFACT_NAME)));
        assertEquals(1, fileCount(artifactsDir));
        verify(metadataStorage).addBuildEntry(BUILD_ID, ProvenancePublisher.METADATA_PROVIDER_ID,
                ProvenancePublisher.ARTIFACT_PATH, METADATA, true);

        InOrder locking = inOrder(artifactsGuard);
        locking.verify(artifactsGuard).lockWriting(artifactsDir.toFile());
        locking.verify(artifactsGuard).unlockWriting(artifactsDir.toFile());
    }

    @Test
    void releasesWriteLockWhenArtifactDirectoryCannotBeCreated(@TempDir Path tempDir) throws Exception {
        Path artifactsPath = tempDir.resolve("artifacts");
        Files.writeString(artifactsPath, "not a directory");
        SBuild build = build(artifactsPath);

        assertThrows(ProvenancePublishingException.class, () -> publisher.publish(build, BUNDLE, METADATA));

        verify(artifactsGuard).lockWriting(artifactsPath.toFile());
        verify(artifactsGuard).unlockWriting(artifactsPath.toFile());
        verify(metadataStorage, never()).addBuildEntry(BUILD_ID, ProvenancePublisher.METADATA_PROVIDER_ID,
                ProvenancePublisher.ARTIFACT_PATH, METADATA, true);
    }

    @Test
    void removesTemporaryFileWhenAtomicMoveFails(@TempDir Path artifactsDir) throws Exception {
        Path targetDirectory = Files.createDirectory(artifactsDir.resolve(ProvenancePublisher.ARTIFACT_NAME));
        Files.writeString(targetDirectory.resolve("marker"), "keep");
        SBuild build = build(artifactsDir);

        assertThrows(ProvenancePublishingException.class, () -> publisher.publish(build, BUNDLE, METADATA));

        assertTrue(Files.isDirectory(targetDirectory));
        assertEquals("keep", Files.readString(targetDirectory.resolve("marker")));
        assertEquals(1, fileCount(artifactsDir));
        verify(artifactsGuard).unlockWriting(artifactsDir.toFile());
        verify(metadataStorage, never()).addBuildEntry(BUILD_ID, ProvenancePublisher.METADATA_PROVIDER_ID,
                ProvenancePublisher.ARTIFACT_PATH, METADATA, true);
    }

    @Test
    void keepsCompletedArtifactWhenMetadataIndexingFails(@TempDir Path artifactsDir) throws Exception {
        SBuild build = build(artifactsDir);
        doThrow(new IllegalStateException("metadata unavailable"))
                .when(metadataStorage)
                .addBuildEntry(BUILD_ID, ProvenancePublisher.METADATA_PROVIDER_ID,
                        ProvenancePublisher.ARTIFACT_PATH, METADATA, true);

        publisher.publish(build, BUNDLE, METADATA);

        assertArrayEquals(BUNDLE, Files.readAllBytes(artifactsDir.resolve(ProvenancePublisher.ARTIFACT_NAME)));
        assertEquals(1, fileCount(artifactsDir));
        verify(artifactsGuard).unlockWriting(artifactsDir.toFile());
    }

    private static SBuild build(Path artifactsDir) {
        SBuild build = mock(SBuild.class);
        when(build.getBuildId()).thenReturn(BUILD_ID);
        when(build.getArtifactsDirectory()).thenReturn(artifactsDir.toFile());
        return build;
    }

    private static long fileCount(Path directory) throws IOException {
        try (var files = Files.list(directory)) {
            return files.count();
        }
    }
}
