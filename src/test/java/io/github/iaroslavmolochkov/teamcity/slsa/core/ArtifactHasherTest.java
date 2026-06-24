package io.github.iaroslavmolochkov.teamcity.slsa.core;

import io.github.iaroslavmolochkov.teamcity.slsa.provenance.ArtifactSubject;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.Sha256Handler;
import jetbrains.buildServer.serverSide.SBuild;
import jetbrains.buildServer.serverSide.artifacts.BuildArtifact;
import jetbrains.buildServer.serverSide.artifacts.BuildArtifacts;
import jetbrains.buildServer.serverSide.artifacts.BuildArtifactsViewMode;
import jetbrains.buildServer.util.EventDispatcher;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ArtifactHasherTest {

    @SuppressWarnings("unchecked")
    private ArtifactHasher newHasher() {
        return new ArtifactHasher(mock(EventDispatcher.class), new Sha256Handler());
    }

    @Test
    void hashesAllFilesInOrderWithCorrectDigests() {
        List<BuildArtifact> files = new ArrayList<>();
        for (int i = 0; i < 50; i++) {
            files.add(fileArtifact("dir/file-" + i + ".bin", ("content-" + i).getBytes(StandardCharsets.UTF_8)));
        }

        SBuild build = buildWith(files);
        List<ArtifactSubject> subjects = newHasher().hash(build);

        assertEquals(files.size(), subjects.size());
        for (int i = 0; i < files.size(); i++) {
            assertEquals("dir/file-" + i + ".bin", subjects.get(i).path());
            assertEquals(new Sha256Handler().hex(("content-" + i).getBytes(StandardCharsets.UTF_8)), subjects.get(i).sha256());
        }
    }

    @Test
    void returnsEmptyWhenArtifactsUnavailable() {
        SBuild build = mock(SBuild.class);
        BuildArtifacts artifacts = mock(BuildArtifacts.class);
        when(build.getArtifacts(any(BuildArtifactsViewMode.class))).thenReturn(artifacts);
        when(artifacts.isAvailable()).thenReturn(false);

        assertEquals(List.of(), newHasher().hash(build));
    }

    private static BuildArtifact fileArtifact(String path, byte[] content) {
        BuildArtifact artifact = mock(BuildArtifact.class);
        when(artifact.isFile()).thenReturn(true);
        when(artifact.getRelativePath()).thenReturn(path);
        when(artifact.getSize()).thenReturn((long) content.length);
        try {
            when(artifact.getInputStream()).thenReturn(new ByteArrayInputStream(content));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return artifact;
    }

    private static SBuild buildWith(List<BuildArtifact> files) {
        SBuild build = mock(SBuild.class);
        when(build.getBuildId()).thenReturn(1L);
        BuildArtifacts artifacts = mock(BuildArtifacts.class);
        when(build.getArtifacts(any(BuildArtifactsViewMode.class))).thenReturn(artifacts);
        when(artifacts.isAvailable()).thenReturn(true);
        doAnswer(invocation -> {
            BuildArtifacts.BuildArtifactsProcessor processor = invocation.getArgument(0);
            for (BuildArtifact file : files) {
                processor.processBuildArtifact(file);
            }
            return null;
        }).when(artifacts).iterateArtifacts(any());
        return build;
    }
}
