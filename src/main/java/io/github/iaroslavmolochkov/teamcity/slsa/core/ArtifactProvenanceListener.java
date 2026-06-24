package io.github.iaroslavmolochkov.teamcity.slsa.core;

import jetbrains.buildServer.serverSide.BuildServerAdapter;
import jetbrains.buildServer.serverSide.BuildServerListener;
import jetbrains.buildServer.serverSide.SRunningBuild;
import jetbrains.buildServer.util.EventDispatcher;
import org.springframework.stereotype.Component;

/**
 * Thin {@link BuildServerListener} adapter: hands every finished build to {@link ProvenanceService},
 * which validates the provenance feature and signs it synchronously, reporting a build problem on failure.
 *
 * <p>All artifact access and signing happen on the server — never on the agent — and the signing key
 * lives only in KMS (or the server's own key), so the build cannot forge its own provenance.
 */
@Component
public class ArtifactProvenanceListener extends BuildServerAdapter {

    private final ProvenanceService provenanceService;

    public ArtifactProvenanceListener(EventDispatcher<BuildServerListener> dispatcher,
                                      ProvenanceService provenanceService) {
        this.provenanceService = provenanceService;
        dispatcher.addListener(this);
    }

    @Override
    public void buildFinished(SRunningBuild build) {
        provenanceService.onBuildFinished(build);
    }
}
