package io.github.iaroslavmolochkov.teamcity.slsa;

import io.github.iaroslavmolochkov.teamcity.slsa.run.ProvenanceService;
import jetbrains.buildServer.serverSide.BuildServerAdapter;
import jetbrains.buildServer.serverSide.BuildServerListener;
import jetbrains.buildServer.serverSide.SRunningBuild;
import jetbrains.buildServer.util.EventDispatcher;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;

/**
 * Thin {@link BuildServerListener} adapter: hands every finished build to {@link ProvenanceService},
 * which validates the provenance feature synchronously (reporting a build problem if it's invalid)
 * and signs asynchronously so the build-finishing thread isn't blocked on hashing or KMS calls.
 *
 * <p>All artifact access and signing happen on the server — never on the agent — and the signing key
 * lives only in KMS (or the server's own key), so the build cannot forge its own provenance.
 */
@Component
public class ArtifactProvenanceListener extends BuildServerAdapter {

    private final ProvenanceService provenanceService;

    public ArtifactProvenanceListener(@NotNull EventDispatcher<BuildServerListener> dispatcher,
                                      @NotNull ProvenanceService provenanceService) {
        this.provenanceService = provenanceService;
        dispatcher.addListener(this);
    }

    @Override
    public void buildFinished(@NotNull SRunningBuild build) {
        provenanceService.onBuildFinished(build);
    }
}
