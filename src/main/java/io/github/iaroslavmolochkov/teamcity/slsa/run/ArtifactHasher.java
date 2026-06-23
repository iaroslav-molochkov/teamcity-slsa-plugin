package io.github.iaroslavmolochkov.teamcity.slsa.run;

import com.intellij.openapi.diagnostic.Logger;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.ArtifactSubject;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.Sha256;
import jetbrains.buildServer.log.Loggers;
import jetbrains.buildServer.serverSide.BuildServerAdapter;
import jetbrains.buildServer.serverSide.BuildServerListener;
import jetbrains.buildServer.serverSide.SBuild;
import jetbrains.buildServer.serverSide.TeamCityProperties;
import jetbrains.buildServer.serverSide.artifacts.BuildArtifact;
import jetbrains.buildServer.serverSide.artifacts.BuildArtifacts;
import jetbrains.buildServer.serverSide.artifacts.BuildArtifactsViewMode;
import jetbrains.buildServer.util.EventDispatcher;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;

/**
 * Hashes a finished build's file artifacts <em>in parallel</em> on a bounded pool, streaming each
 * artifact (so artifact size doesn't drive memory). Returns one {@link ArtifactSubject} per file,
 * in artifact-iteration order.
 */
@Component
public class ArtifactHasher {

    private static final Logger LOG = Loggers.SERVER;

    /** Server property to override the hashing pool size; defaults to the CPU count. */
    public static final String HASH_THREADS_PROPERTY = "teamcity.slsa.hashThreads";

    private final ExecutorService pool;

    public ArtifactHasher(@NotNull EventDispatcher<BuildServerListener> eventDispatcher) {
        int threads = TeamCityProperties.getInteger(HASH_THREADS_PROPERTY, SlsaExecutors.defaultPoolSize());
        pool = SlsaExecutors.fixedDaemonPool(threads, "slsa-hash");
        eventDispatcher.addListener(new BuildServerAdapter() {
            @Override
            public void serverShutdown() {
                pool.shutdownNow();
            }
        });
    }

    /** Streams and hashes every file artifact of the build concurrently. */
    @NotNull
    public List<ArtifactSubject> hash(@NotNull SBuild build) {
        BuildArtifacts artifacts = build.getArtifacts(BuildArtifactsViewMode.VIEW_DEFAULT);

        if (!artifacts.isAvailable()) {
            return List.of();
        }

        List<BuildArtifact> files = new ArrayList<>();
        artifacts.iterateArtifacts(artifact -> {
            if (artifact.isFile()) {
                files.add(artifact);
            }
            return BuildArtifacts.BuildArtifactsProcessor.Continuation.CONTINUE;
        });

        if (files.isEmpty()) {
            return List.of();
        }

        List<CompletableFuture<ArtifactSubject>> futures = new ArrayList<>(files.size());

        for (BuildArtifact artifact : files) {
            futures.add(CompletableFuture.supplyAsync(() -> toSubject(build, artifact), pool));
        }

        //todo if build error then probably useless? but unconfirmed
        List<ArtifactSubject> subjects = new ArrayList<>(files.size());

        for (CompletableFuture<ArtifactSubject> future : futures) {
            ArtifactSubject subject = future.join();
            if (subject != null) {
                subjects.add(subject);
            }
        }

        return subjects;
    }

    private ArtifactSubject toSubject(@NotNull SBuild build, @NotNull BuildArtifact artifact) {
        //todo retry4j?
        try (InputStream in = artifact.getInputStream()) {
            ArtifactSubject subject = new ArtifactSubject(artifact.getRelativePath(), artifact.getSize(), Sha256.hex(in));
            //todo is log debug enabled redundant if lambda?
            if (LOG.isDebugEnabled()) {
                LOG.debug("SLSA:   " + subject.path() + " (" + subject.size() + " bytes) sha256:" + subject.sha256());
            }
            return subject;
        } catch (Exception e) {
            LOG.warnAndDebugDetails("SLSA: failed to digest artifact " + artifact.getRelativePath()
                    + " of build " + build.getBuildId(), e);
            //todo fail build? if users use sigs then it's important and can't ship wihtout them?
            return null;
        }
    }
}
