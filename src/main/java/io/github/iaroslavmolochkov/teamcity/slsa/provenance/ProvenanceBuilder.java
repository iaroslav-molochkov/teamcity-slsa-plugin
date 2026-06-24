package io.github.iaroslavmolochkov.teamcity.slsa.provenance;

import com.intellij.openapi.diagnostic.Logger;
import jetbrains.buildServer.log.Loggers;
import jetbrains.buildServer.serverSide.Branch;
import jetbrains.buildServer.serverSide.BuildRevision;
import jetbrains.buildServer.serverSide.SBuild;
import jetbrains.buildServer.serverSide.SBuildServer;
import jetbrains.buildServer.serverSide.TriggeredBy;
import jetbrains.buildServer.serverSide.dependency.BuildDependency;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.intoto.InTotoStatement;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.intoto.Subject;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.slsa.BuildDefinition;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.slsa.ResolvedDependency;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.slsa.RunDetails;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.slsa.RunMetadata;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.slsa.SlsaPlatform;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.slsa.SlsaPredicate;
import jetbrains.buildServer.serverSide.crypt.EncryptUtil;
import jetbrains.buildServer.users.SUser;
import jetbrains.buildServer.vcs.SVcsModification;
import jetbrains.buildServer.vcs.VcsRootInstance;
import jetbrains.buildServer.vcs.VcsRootNotFoundException;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Builds the SLSA v1.0 {@link InTotoStatement} for a finished build from server-side data only. */
@Component
public class ProvenanceBuilder {

    /** Identifies this plugin's build type/template in the provenance. */
    public static final String BUILD_TYPE = "https://iaroslav-molochkov.github.io/teamcity-slsa-plugin/buildtype/v1";

    private static final Logger log = Loggers.SERVER;

    private final SBuildServer server;

    public ProvenanceBuilder(SBuildServer server) {
        this.server = server;
    }

    public InTotoStatement build(SBuild build, List<ArtifactSubject> subjects) {
        List<Subject> wireSubjects = new ArrayList<>(subjects.size());

        for (ArtifactSubject artifact : subjects) {
            wireSubjects.add(new Subject(artifact.path(), Map.of("sha256", artifact.sha256())));
        }

        SlsaPredicate predicate = new SlsaPredicate(
                new BuildDefinition(
                        BUILD_TYPE,
                        externalParameters(build),
                        internalParameters(build),
                        resolvedDependencies(build)),
                new RunDetails(
                        new SlsaPlatform(builderId(), builderVersion()),
                        new RunMetadata(
                                buildUrl(build),
                                iso(build.getStartDate()),
                                iso(build.getFinishDate()))));

        return new InTotoStatement(InTotoStatement.TYPE, wireSubjects, InTotoStatement.SLSA_PREDICATE_TYPE, predicate);
    }

    /** Platform identity — the TeamCity server instance that produced the provenance. */
    private String builderId() {
        return trimTrailingSlash(server.getRootUrl());
    }

    /** Run identity — the URL of this specific build. */
    private String buildUrl(SBuild build) {
        return builderId() + "/viewLog.html?buildId=" + build.getBuildId()
                + "&buildTypeId=" + build.getBuildTypeExternalId();
    }

    private Map<String, Object> externalParameters(SBuild build) {
        Map<String, Object> params = new HashMap<>();

        params.put("buildTypeId", build.getBuildTypeExternalId());
        params.put("buildTypeName", build.getFullName());
        params.put("buildNumber", build.getBuildNumber());
        params.put("triggeredBy", triggeredBy(build));

        Branch branch = build.getBranch();

        if (branch != null) {
            params.put("branch", branch.getName());
        }

        Map<String, String> configParams = new HashMap<>();

        for (Map.Entry<String, String> param : build.getBuildOwnParameters().entrySet()) {
            if (isSafe(param.getKey(), param.getValue())) {
                configParams.put(param.getKey(), param.getValue());
            }
        }

        if (!configParams.isEmpty()) {
            params.put("buildParameters", configParams);
        }

        return params;
    }

    private Map<String, Object> internalParameters(SBuild build) {
        Map<String, Object> params = new HashMap<>();
        params.put("teamcityVersion", server.getFullServerVersion());
        params.put("projectId", build.getProjectExternalId());

        String agent = build.getAgentName();

        if (agent != null && !agent.isEmpty()) {
            params.put("agentName", agent);
        }

        String agentHost = build.getAgent().getHostName();

        if (agentHost != null && !agentHost.isEmpty()) {
            params.put("agentHostName", agentHost);
        }

        if (build.isPersonal()) {
            params.put("personal", true);
        }

        return params;
    }

    /** The request origin: the triggering user, a snapshot dependency, or the trigger type id. */
    private String triggeredBy(SBuild build) {
        TriggeredBy triggeredBy = build.getTriggeredBy();
        SUser user = triggeredBy.getUser();
        if (user != null) {
            return "user:" + user.getUsername();
        }
        if (triggeredBy.isTriggeredBySnapshotDependency()) {
            return "snapshotDependency";
        }
        String triggerId = triggeredBy.getTriggerId();
        return (triggerId != null && !triggerId.isEmpty()) ? triggerId : "unknown";
    }

    private List<ResolvedDependency> resolvedDependencies(SBuild build) {
        Map<String, SVcsModification> commits = changesByRootAndVersion(build);
        List<ResolvedDependency> deps = new ArrayList<>();

        for (BuildRevision revision : build.getRevisions()) {
            VcsRootInstance root = revision.getRoot();
            String revisionSha = revision.getRevision();

            Map<String, String> annotations = new HashMap<>();
            String branch = revision.getRepositoryVersion().getVcsBranch();

            if (branch != null && !branch.isEmpty()) {
                annotations.put("branch", branch);
            }

            SVcsModification commit = commits.get(root.getId() + "@" + revisionSha);

            if (commit != null) {
                putIfNotEmpty(annotations, "author", commit.getUserName());
                putIfNotEmpty(annotations, "message", firstLine(commit.getDescription()));
                putIfNotEmpty(annotations, "committedAt", iso(commit.getVcsDate()));
            }

            deps.add(new ResolvedDependency(
                    gitUri(root),
                    Map.of("gitCommit", revisionSha),
                    root.getName(),
                    annotations.isEmpty() ? null : annotations));
        }

        Set<Long> seenBuilds = new HashSet<>();

        for (BuildDependency dependency : build.getBuildPromotion().getDependencies()) {
            SBuild upstream = dependency.getDependOn().getAssociatedBuild();

            if (upstream == null || !seenBuilds.add(upstream.getBuildId())) {
                continue;
            }

            deps.add(new ResolvedDependency(
                    buildUrl(upstream),
                    null,
                    upstream.getBuildTypeExternalId() + " #" + upstream.getBuildNumber(),
                    null
                    )
            );

        }

        return deps;
    }

    /** Indexes the build's contained changes by {@code <rootId>@<version>} for commit lookup. */
    private Map<String, SVcsModification> changesByRootAndVersion(SBuild build) {
        Map<String, SVcsModification> byRootVersion = new HashMap<>();

        for (SVcsModification change : build.getContainingChanges()) {
            try {
                byRootVersion.put(change.getVcsRoot().getId() + "@" + change.getVersion(), change);
            } catch (VcsRootNotFoundException e) {
                log.warn("SLSA: VCS root for change " + change.getVersion()
                        + " not found; skipping its commit enrichment", e);
            }
        }

        return byRootVersion;
    }

    private String gitUri(VcsRootInstance root) {
        String url = root.getProperty("url");
        String base = (url != null && !url.isEmpty()) ? url : root.getName();
        String vcsName = root.getVcsName();

        if (vcsName.toLowerCase(Locale.ROOT).contains("git") && !base.startsWith("git+")) {
            return "git+" + base;
        }

        return base;
    }

    private void putIfNotEmpty(Map<String, String> map, String key, String value) {
        if (value == null) {
            return;
        }
        String trimmed = value.trim();
        if (!trimmed.isEmpty()) {
            map.put(key, trimmed);
        }
    }

    private String firstLine(String text) {
        if (text == null) {
            return "";
        }

        int newline = text.indexOf('\n');
        String line = (newline >= 0 ? text.substring(0, newline) : text).trim();
        return line.length() > 200 ? line.substring(0, 200) + "…" : line;
    }

    private Map<String, String> builderVersion() {
        return Map.of("teamcity", server.getFullServerVersion());
    }

    private boolean isSafe(String key, String value) {
        if (value == null) {
            return false;
        }

        if (key.startsWith("secure:")) {
            return false;
        }

        return !EncryptUtil.isScrambled(value);
    }

    private String iso(Date date) {
        return date == null ? null : DateTimeFormatter.ISO_INSTANT.format(Instant.ofEpochMilli(date.getTime()));
    }

    private String trimTrailingSlash(String s) {
        return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }
}
