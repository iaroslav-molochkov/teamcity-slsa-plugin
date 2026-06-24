package io.github.iaroslavmolochkov.teamcity.slsa.provenance;

import io.github.iaroslavmolochkov.teamcity.slsa.provenance.intoto.InTotoStatement;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.slsa.ResolvedDependency;
import jetbrains.buildServer.serverSide.BuildPromotion;
import jetbrains.buildServer.serverSide.BuildRevision;
import jetbrains.buildServer.serverSide.RepositoryVersion;
import jetbrains.buildServer.serverSide.SBuild;
import jetbrains.buildServer.serverSide.SBuildAgent;
import jetbrains.buildServer.serverSide.SBuildServer;
import jetbrains.buildServer.serverSide.TriggeredBy;
import jetbrains.buildServer.serverSide.dependency.BuildDependency;
import jetbrains.buildServer.users.SUser;
import jetbrains.buildServer.vcs.SVcsModification;
import jetbrains.buildServer.vcs.VcsRootInstance;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ProvenanceBuilderTest {

    @Test
    @SuppressWarnings("unchecked")
    void mapsBuildToSlsaStatement() {
        SBuildServer server = mock(SBuildServer.class);
        when(server.getRootUrl()).thenReturn("https://tc.example.com/");
        when(server.getFullServerVersion()).thenReturn("TeamCity 2025.07 (build 999)");

        Map<String, String> ownParams = new LinkedHashMap<>();
        ownParams.put("env.FOO", "bar");
        ownParams.put("secure:token", "should-be-dropped");

        SBuild build = mock(SBuild.class);
        when(build.getBuildId()).thenReturn(42L);
        when(build.getBuildTypeExternalId()).thenReturn("MyProj_Build");
        when(build.getFullName()).thenReturn("MyProj / Build");
        when(build.getBuildNumber()).thenReturn("1.0.1");
        when(build.getBranch()).thenReturn(null);
        when(build.getAgentName()).thenReturn("agent-1");
        when(build.getBuildOwnParameters()).thenReturn(ownParams);
        when(build.getRevisions()).thenReturn(List.of());
        when(build.getStartDate()).thenReturn(new Date(1000));
        when(build.getFinishDate()).thenReturn(new Date(5000));
        when(build.getProjectExternalId()).thenReturn("MyProj");

        stubPlatform(build);
        SUser user = mock(SUser.class);
        when(user.getUsername()).thenReturn("jdoe");
        TriggeredBy triggeredBy = mock(TriggeredBy.class);
        when(triggeredBy.getUser()).thenReturn(user);
        when(build.getTriggeredBy()).thenReturn(triggeredBy);
        SBuildAgent agent = mock(SBuildAgent.class);
        when(agent.getHostName()).thenReturn("agent-host-1");
        when(build.getAgent()).thenReturn(agent);

        ProvenanceBuilder builder = new ProvenanceBuilder(server);
        InTotoStatement statement = builder.build(build,
                List.of(new ArtifactSubject("dist/app.jar", 10, "abcd1234")));

        assertEquals(InTotoStatement.TYPE, statement.type());
        assertEquals(InTotoStatement.SLSA_PREDICATE_TYPE, statement.predicateType());

        assertEquals(1, statement.subject().size());
        assertEquals("dist/app.jar", statement.subject().get(0).name());
        assertEquals("abcd1234", statement.subject().get(0).digest().get("sha256"));

        assertEquals("https://tc.example.com", statement.predicate().runDetails().builder().id());
        String invocation = "https://tc.example.com/viewLog.html?buildId=42&buildTypeId=MyProj_Build";
        assertEquals(invocation, statement.predicate().runDetails().metadata().invocationId());
        assertEquals("1970-01-01T00:00:01Z", statement.predicate().runDetails().metadata().startedOn());
        assertEquals("1970-01-01T00:00:05Z", statement.predicate().runDetails().metadata().finishedOn());

        Map<String, Object> external = statement.predicate().buildDefinition().externalParameters();
        Map<String, String> buildParams = (Map<String, String>) external.get("buildParameters");
        assertTrue(buildParams.containsKey("env.FOO"));
        assertFalse(buildParams.containsKey("secure:token"), "secret params must be excluded");
        assertEquals("user:jdoe", external.get("triggeredBy"));

        Map<String, Object> internal = statement.predicate().buildDefinition().internalParameters();
        assertEquals("MyProj", internal.get("projectId"));
        assertEquals("agent-host-1", internal.get("agentHostName"));
        assertFalse(internal.containsKey("personal"), "non-personal builds omit the flag");
    }

    @Test
    void enrichesSourceWithCommitAndBranch() {
        SBuildServer server = mock(SBuildServer.class);
        when(server.getRootUrl()).thenReturn("https://tc.example.com");
        when(server.getFullServerVersion()).thenReturn("TeamCity 2025.07");

        VcsRootInstance root = mock(VcsRootInstance.class);
        when(root.getId()).thenReturn(7L);
        when(root.getName()).thenReturn("app-repo");
        when(root.getProperty("url")).thenReturn("https://github.com/acme/app.git");
        when(root.getVcsName()).thenReturn("jetbrains.git");

        RepositoryVersion repoVersion = mock(RepositoryVersion.class);
        when(repoVersion.getVcsBranch()).thenReturn("refs/heads/main");

        BuildRevision revision = mock(BuildRevision.class);
        when(revision.getRoot()).thenReturn(root);
        when(revision.getRevision()).thenReturn("abc123");
        when(revision.getRepositoryVersion()).thenReturn(repoVersion);

        SVcsModification commit = mock(SVcsModification.class);
        when(commit.getVcsRoot()).thenReturn(root);
        when(commit.getVersion()).thenReturn("abc123");
        when(commit.getUserName()).thenReturn("Jane Dev");
        when(commit.getDescription()).thenReturn("Fix the bug\n\nlong details");
        when(commit.getVcsDate()).thenReturn(new Date(2000));

        SBuild build = mock(SBuild.class);
        when(build.getBuildId()).thenReturn(1L);
        when(build.getBuildTypeExternalId()).thenReturn("Bt");
        when(build.getFullName()).thenReturn("P / Bt");
        when(build.getBuildNumber()).thenReturn("1");
        when(build.getBranch()).thenReturn(null);
        when(build.getAgentName()).thenReturn("a");
        when(build.getBuildOwnParameters()).thenReturn(Map.of());
        when(build.getStartDate()).thenReturn(new Date(0));
        when(build.getFinishDate()).thenReturn(new Date(0));
        when(build.getRevisions()).thenReturn(List.of(revision));
        when(build.getContainingChanges()).thenReturn(List.of(commit));
        stubPlatform(build);

        ProvenanceBuilder builder = new ProvenanceBuilder(server);
        InTotoStatement statement = builder.build(build,
                List.of(new ArtifactSubject("app.jar", 1, "deadbeef")));

        List<ResolvedDependency> deps =
                statement.predicate().buildDefinition().resolvedDependencies();
        assertEquals(1, deps.size());
        ResolvedDependency dep = deps.get(0);
        assertEquals("git+https://github.com/acme/app.git", dep.uri());
        assertEquals("abc123", dep.digest().get("gitCommit"));
        assertEquals("app-repo", dep.name());
        assertEquals("refs/heads/main", dep.annotations().get("branch"));
        assertEquals("Jane Dev", dep.annotations().get("author"));
        assertEquals("Fix the bug", dep.annotations().get("message"));
        assertEquals("1970-01-01T00:00:02Z", dep.annotations().get("committedAt"));

        String json = new String(new ProvenanceJsonHandler().toBytes(statement), java.nio.charset.StandardCharsets.UTF_8);
        assertTrue(json.contains("\"gitCommit\":\"abc123\""), json);
        assertTrue(json.contains("\"predicateType\":\"" + InTotoStatement.SLSA_PREDICATE_TYPE + "\""), json);
        assertTrue(json.contains("git+https://github.com/acme/app.git"), json);
    }

    @Test
    void includesUpstreamBuildDependencies() {
        SBuildServer server = mock(SBuildServer.class);
        when(server.getRootUrl()).thenReturn("https://tc.example.com");
        when(server.getFullServerVersion()).thenReturn("TeamCity 2026.1");

        SBuild upstream = mock(SBuild.class);
        when(upstream.getBuildId()).thenReturn(7L);
        when(upstream.getBuildTypeExternalId()).thenReturn("Lib_Build");
        when(upstream.getBuildNumber()).thenReturn("3.2");

        BuildPromotion upstreamPromotion = mock(BuildPromotion.class);
        when(upstreamPromotion.getAssociatedBuild()).thenReturn(upstream);
        BuildDependency dependency = mock(BuildDependency.class);
        when(dependency.getDependOn()).thenReturn(upstreamPromotion);

        SBuild build = mock(SBuild.class);
        when(build.getBuildId()).thenReturn(1L);
        when(build.getBuildTypeExternalId()).thenReturn("App_Build");
        when(build.getFullName()).thenReturn("App / Build");
        when(build.getBuildNumber()).thenReturn("1");
        when(build.getBranch()).thenReturn(null);
        when(build.getAgentName()).thenReturn("a");
        when(build.getBuildOwnParameters()).thenReturn(Map.of());
        when(build.getStartDate()).thenReturn(new Date(0));
        when(build.getFinishDate()).thenReturn(new Date(0));
        when(build.getRevisions()).thenReturn(List.of());
        stubPlatform(build);
        BuildPromotion promotion = mock(BuildPromotion.class);
        doReturn(List.of(dependency, dependency)).when(promotion).getDependencies();
        when(build.getBuildPromotion()).thenReturn(promotion);

        ProvenanceBuilder builder = new ProvenanceBuilder(server);
        InTotoStatement statement = builder.build(build,
                List.of(new ArtifactSubject("app.jar", 1, "deadbeef")));

        List<ResolvedDependency> deps =
                statement.predicate().buildDefinition().resolvedDependencies();
        assertEquals(1, deps.size());
        assertEquals("https://tc.example.com/viewLog.html?buildId=7&buildTypeId=Lib_Build", deps.get(0).uri());
        assertEquals("Lib_Build #3.2", deps.get(0).name());
    }

    private static void stubPlatform(SBuild build) {
        TriggeredBy triggeredBy = mock(TriggeredBy.class);
        when(triggeredBy.getTriggerId()).thenReturn("vcsTrigger");
        when(build.getTriggeredBy()).thenReturn(triggeredBy);

        when(build.getAgent()).thenReturn(mock(SBuildAgent.class));

        BuildPromotion promotion = mock(BuildPromotion.class);
        when(promotion.getDependencies()).thenReturn(List.of());
        when(build.getBuildPromotion()).thenReturn(promotion);
    }
}
