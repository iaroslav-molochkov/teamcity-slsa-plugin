package io.github.iaroslavmolochkov.slsa.core;

import jetbrains.buildServer.serverSide.BuildServerAdapter;
import jetbrains.buildServer.serverSide.BuildServerListener;
import jetbrains.buildServer.serverSide.SRunningBuild;
import jetbrains.buildServer.util.EventDispatcher;
import org.springframework.stereotype.Component;

/** Hands every finished build to {@link ProvenanceService}. */
@Component
public class ArtifactProvenanceListener extends BuildServerAdapter {

    private final ProvenanceService provenanceService;

    public ArtifactProvenanceListener(EventDispatcher<BuildServerListener> dispatcher,
                                      ProvenanceService provenanceService) {
        this.provenanceService = provenanceService;
        dispatcher.addListener(this);
    }

    @Override
    @SuppressWarnings("NullableProblems")
    public void buildFinished(SRunningBuild build) {
        provenanceService.onBuildFinished(build);
    }
}
