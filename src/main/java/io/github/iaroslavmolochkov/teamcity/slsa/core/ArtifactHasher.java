package io.github.iaroslavmolochkov.teamcity.slsa.core;

import com.intellij.openapi.diagnostic.Logger;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.ArtifactSubject;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.Sha256Handler;
import jetbrains.buildServer.log.Loggers;
import jetbrains.buildServer.serverSide.BuildServerAdapter;
import jetbrains.buildServer.serverSide.BuildServerListener;
import jetbrains.buildServer.serverSide.SBuild;
import jetbrains.buildServer.serverSide.TeamCityProperties;
import jetbrains.buildServer.serverSide.artifacts.BuildArtifact;
import jetbrains.buildServer.serverSide.artifacts.BuildArtifacts;
import jetbrains.buildServer.serverSide.artifacts.BuildArtifactsViewMode;
import jetbrains.buildServer.util.EventDispatcher;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Hashes a finished build's file artifacts <em>in parallel</em> on a bounded pool, streaming each
 * artifact (so artifact size doesn't drive memory). Returns one {@link ArtifactSubject} per file,
 * in artifact-iteration order.
 */
@Component
public class ArtifactHasher {

    private static final Logger log = Loggers.SERVER;

    /** Server property to override the hashing pool size; defaults to the CPU count. */
    public static final String HASH_THREADS_PROPERTY = "teamcity.slsa.hashThreads";

    private final ExecutorService pool;
    private final Sha256Handler sha256;

    public ArtifactHasher(EventDispatcher<BuildServerListener> eventDispatcher, Sha256Handler sha256) {
        this.sha256 = sha256;
        int threads = TeamCityProperties.getInteger(HASH_THREADS_PROPERTY, Math.max(2, Runtime.getRuntime().availableProcessors()));
        pool = Executors.newFixedThreadPool(threads, daemonThreadFactory("slsa-hash"));
        eventDispatcher.addListener(new BuildServerAdapter() {
            @Override
            public void serverShutdown() {
                pool.shutdownNow();
            }
        });
    }

    private ThreadFactory daemonThreadFactory(String namePrefix) {
        AtomicInteger counter = new AtomicInteger();
        return runnable -> {
            Thread thread = new Thread(runnable, namePrefix + "-" + counter.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        };
    }

    /** Streams and hashes every file artifact of the build concurrently. */
    public List<ArtifactSubject> hash(SBuild build) {
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

        List<ArtifactSubject> subjects = new ArrayList<>(files.size());

        try {
            for (CompletableFuture<ArtifactSubject> future : futures) {
                subjects.add(future.join());
            }
        } catch (CompletionException e) {
            futures.forEach(future -> future.cancel(true));
            Throwable cause = e.getCause();
            throw cause instanceof HashingException hashing
                    ? hashing
                    : new HashingException("Failed to hash artifacts of build " + build.getBuildId(), cause);
        }

        return subjects;
    }

    private ArtifactSubject toSubject(SBuild build, BuildArtifact artifact) {
        //todo retry4j?
        try (InputStream in = artifact.getInputStream()) {
            ArtifactSubject subject = new ArtifactSubject(artifact.getRelativePath(), artifact.getSize(), sha256.hex(in));

            if (log.isDebugEnabled()) {
                log.debug("SLSA:   " + subject.path() + " (" + subject.size() + " bytes) sha256:" + subject.sha256());
            }

            return subject;
        } catch (Exception e) {
            log.warnAndDebugDetails("SLSA: failed to digest artifact " + artifact.getRelativePath()
                    + " of build " + build.getBuildId(), e);
            throw new HashingException("Failed to digest artifact " + artifact.getRelativePath()
                    + " of build " + build.getBuildId(), e);
        }
    }
}
