package io.github.iaroslavmolochkov.teamcity.slsa.provenance;

import io.github.iaroslavmolochkov.teamcity.slsa.provenance.intoto.InTotoStatement;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.slsa.ExternalParameters;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.slsa.InternalParameters;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.slsa.ResolvedDependency;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.slsa.Trigger;
import jetbrains.buildServer.serverSide.Branch;
import jetbrains.buildServer.serverSide.BuildPromotion;
import jetbrains.buildServer.serverSide.BuildRevision;
import jetbrains.buildServer.serverSide.RepositoryVersion;
import jetbrains.buildServer.serverSide.SBuild;
import jetbrains.buildServer.serverSide.SBuildAgent;
import jetbrains.buildServer.serverSide.SBuildServer;
import jetbrains.buildServer.serverSide.TriggeredBy;
import jetbrains.buildServer.serverSide.WebLinks;
import jetbrains.buildServer.serverSide.dependency.BuildDependency;
import jetbrains.buildServer.users.SUser;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import jetbrains.buildServer.vcs.SVcsModification;
import jetbrains.buildServer.vcs.VcsRootInstance;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ProvenanceBuilderTest {

    private final PluginDescriptor descriptor = mock(PluginDescriptor.class);
    private final BuildParameterFilter parameterFilter = mock(BuildParameterFilter.class);

    @Test
    void mapsBuildToSlsaStatement() {
        SBuildServer server = mock(SBuildServer.class);
        when(server.getFullServerVersion()).thenReturn("TeamCity 2025.07 (build 999)");

        WebLinks webLinks = mock(WebLinks.class);
        when(webLinks.getRootUrlByProjectExternalId(any())).thenReturn("https://tc.example.com");

        SBuild build = mock(SBuild.class);
        when(webLinks.getViewResultsUrl(build))
                .thenReturn("https://tc.example.com/buildConfiguration/MyProj_Build/42");
        when(build.getBuildId()).thenReturn(42L);
        when(build.getBuildTypeExternalId()).thenReturn("MyProj_Build");
        when(build.getBuildTypeName()).thenReturn("Build");
        when(build.getBuildNumber()).thenReturn("1.0.1");
        Branch branch = mock(Branch.class);
        when(branch.getName()).thenReturn("main");
        when(build.getBranch()).thenReturn(branch);
        when(descriptor.getPluginVersion()).thenReturn("0.1.3");
        when(build.getAgentName()).thenReturn("agent-1");
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
        when(agent.getVersion()).thenReturn("2026.1");
        when(agent.getOperatingSystemName()).thenReturn("Linux 6.1");
        when(agent.isCloudAgent()).thenReturn(true);
        when(build.getAgent()).thenReturn(agent);

        ProvenanceBuilder builder = new ProvenanceBuilder(server, webLinks, descriptor, parameterFilter);
        InTotoStatement statement = builder.build(build,
                List.of(new ArtifactSubject("dist/app.jar", 10, "abcd1234")), false);

        assertEquals(InTotoStatement.TYPE, statement.type());
        assertEquals(InTotoStatement.SLSA_PREDICATE_TYPE, statement.predicateType());

        assertEquals(1, statement.subject().size());
        assertEquals("dist/app.jar", statement.subject().get(0).name());
        assertEquals("abcd1234", statement.subject().get(0).digest().get("sha256"));

        assertEquals("https://tc.example.com", statement.predicate().runDetails().builder().id());
        assertEquals("https://tc.example.com/buildConfiguration/MyProj_Build/42",
                statement.predicate().runDetails().metadata().invocationId());
        assertEquals("1970-01-01T00:00:01Z", statement.predicate().runDetails().metadata().startedOn());
        assertEquals("1970-01-01T00:00:05Z", statement.predicate().runDetails().metadata().finishedOn());

        ExternalParameters external = statement.predicate().buildDefinition().externalParameters();
        assertEquals("MyProj_Build", external.buildTypeId());
        assertEquals("MyProj", external.projectId());
        assertEquals("main", external.branch());
        assertNull(external.personal(), "non-personal builds omit the flag");
        assertNull(external.customBuildParameters(), "build parameters omitted unless enabled");

        InternalParameters internal = statement.predicate().buildDefinition().internalParameters();
        assertEquals("1.0.1", internal.buildNumber());
        assertEquals("agent-host-1", internal.agentHostName());
        assertEquals("2026.1", internal.agentVersion());
        assertEquals("Linux 6.1", internal.agentOs());
        assertEquals(true, internal.agentIsCloud());
        assertEquals("user", internal.trigger().type());
        assertEquals("jdoe", internal.trigger().username());

        var versions = statement.predicate().runDetails().builder().componentVersions();
        assertEquals("TeamCity 2025.07 (build 999)", versions.get("teamcity"));
        assertEquals("0.1.3", versions.get("teamcity-slsa-plugin"));
    }

    @Test
    void attributesSuperUserTriggerWhenUsernameAbsent() {
        SBuildServer server = mock(SBuildServer.class);
        when(server.getFullServerVersion()).thenReturn("TeamCity 2026.1");
        WebLinks webLinks = mock(WebLinks.class);
        when(webLinks.getRootUrlByProjectExternalId(any())).thenReturn("https://tc.example.com");

        SBuild build = mock(SBuild.class);
        when(build.getBuildId()).thenReturn(1L);
        when(build.getBuildTypeExternalId()).thenReturn("Bt");
        when(build.getBranch()).thenReturn(null);
        when(build.getRevisions()).thenReturn(List.of());
        when(build.getStartDate()).thenReturn(new Date(0));
        when(build.getFinishDate()).thenReturn(new Date(0));
        when(build.getAgent()).thenReturn(mock(SBuildAgent.class));

        SUser superUser = mock(SUser.class);
        when(superUser.getUsername()).thenReturn(null);
        when(superUser.getId()).thenReturn((long) SUser.SUPER_USER_ID);
        TriggeredBy triggeredBy = mock(TriggeredBy.class);
        when(triggeredBy.getUser()).thenReturn(superUser);
        when(build.getTriggeredBy()).thenReturn(triggeredBy);
        BuildPromotion promotion = mock(BuildPromotion.class);
        when(promotion.getDependencies()).thenReturn(List.of());
        when(build.getBuildPromotion()).thenReturn(promotion);

        ProvenanceBuilder builder = new ProvenanceBuilder(server, webLinks, descriptor, parameterFilter);
        InTotoStatement statement = builder.build(build,
                List.of(new ArtifactSubject("app.jar", 1, "deadbeef")), false);

        Trigger trigger = statement.predicate().buildDefinition().internalParameters().trigger();
        assertEquals("user", trigger.type());
        assertNull(trigger.username(), "super user has no username");
        assertEquals(-42L, trigger.userId());

        String json = new String(new ProvenanceJsonHandler().toBytes(statement), java.nio.charset.StandardCharsets.UTF_8);
        assertTrue(json.contains("\"trigger\":{\"type\":\"user\",\"userId\":-42}"), json);
        assertFalse(json.contains("\"username\""), json);
    }

    @Test
    void fallsBackToPromotionFinishDateWhenRunningBuildHasNone() {
        SBuildServer server = mock(SBuildServer.class);
        when(server.getFullServerVersion()).thenReturn("TeamCity 2026.1");

        WebLinks webLinks = mock(WebLinks.class);
        when(webLinks.getRootUrlByProjectExternalId(any())).thenReturn("https://tc.example.com");

        SBuild build = mock(SBuild.class);
        when(build.getBuildId()).thenReturn(1L);
        when(build.getBuildTypeExternalId()).thenReturn("Bt");
        when(build.getFullName()).thenReturn("P / Bt");
        when(build.getBuildNumber()).thenReturn("1");
        when(build.getBranch()).thenReturn(null);
        when(build.getAgentName()).thenReturn("a");
        when(build.getRevisions()).thenReturn(List.of());
        when(build.getStartDate()).thenReturn(new Date(1000));
        when(build.getFinishDate()).thenReturn(null);

        TriggeredBy triggeredBy = mock(TriggeredBy.class);
        when(triggeredBy.getTriggerId()).thenReturn("vcsTrigger");
        when(build.getTriggeredBy()).thenReturn(triggeredBy);
        when(build.getAgent()).thenReturn(mock(SBuildAgent.class));

        SBuild associated = mock(SBuild.class);
        when(associated.getFinishDate()).thenReturn(new Date(9000));
        BuildPromotion promotion = mock(BuildPromotion.class);
        when(promotion.getDependencies()).thenReturn(List.of());
        when(promotion.getAssociatedBuild()).thenReturn(associated);
        when(build.getBuildPromotion()).thenReturn(promotion);

        ProvenanceBuilder builder = new ProvenanceBuilder(server, webLinks, descriptor, parameterFilter);
        InTotoStatement statement = builder.build(build,
                List.of(new ArtifactSubject("app.jar", 1, "deadbeef")), false);

        assertEquals("1970-01-01T00:00:09Z", statement.predicate().runDetails().metadata().finishedOn());
    }

    @Test
    void enrichesSourceWithCommitAndBranch() {
        SBuildServer server = mock(SBuildServer.class);
        when(server.getFullServerVersion()).thenReturn("TeamCity 2025.07");

        WebLinks webLinks = mock(WebLinks.class);
        when(webLinks.getRootUrlByProjectExternalId(any())).thenReturn("https://tc.example.com");

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
        when(commit.getUserName()).thenReturn("John Doe");
        when(commit.getDescription()).thenReturn("Fix the bug\n\nlong details");
        when(commit.getVcsDate()).thenReturn(new Date(2000));

        SBuild build = mock(SBuild.class);
        when(build.getBuildId()).thenReturn(1L);
        when(build.getBuildTypeExternalId()).thenReturn("Bt");
        when(build.getFullName()).thenReturn("P / Bt");
        when(build.getBuildNumber()).thenReturn("1");
        when(build.getBranch()).thenReturn(null);
        when(build.getAgentName()).thenReturn("a");
        when(build.getStartDate()).thenReturn(new Date(0));
        when(build.getFinishDate()).thenReturn(new Date(0));
        when(build.getRevisions()).thenReturn(List.of(revision));
        when(build.getContainingChanges()).thenReturn(List.of(commit));
        stubPlatform(build);

        ProvenanceBuilder builder = new ProvenanceBuilder(server, webLinks, descriptor, parameterFilter);
        InTotoStatement statement = builder.build(build,
                List.of(new ArtifactSubject("app.jar", 1, "deadbeef")), false);

        List<ResolvedDependency> deps =
                statement.predicate().buildDefinition().resolvedDependencies();
        assertEquals(1, deps.size());
        ResolvedDependency dep = deps.get(0);
        assertEquals("git+https://github.com/acme/app.git", dep.uri());
        assertEquals("abc123", dep.digest().get("gitCommit"));
        assertEquals("app-repo", dep.name());
        assertEquals("refs/heads/main", dep.annotations().get("branch"));
        assertEquals("John Doe", dep.annotations().get("author"));
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
        when(server.getFullServerVersion()).thenReturn("TeamCity 2026.1");

        WebLinks webLinks = mock(WebLinks.class);
        when(webLinks.getRootUrlByProjectExternalId(any())).thenReturn("https://tc.example.com");

        SBuild upstream = mock(SBuild.class);
        when(upstream.getBuildId()).thenReturn(7L);
        when(upstream.getBuildTypeExternalId()).thenReturn("Lib_Build");
        when(upstream.getBuildNumber()).thenReturn("3.2");
        when(webLinks.getViewResultsUrl(upstream))
                .thenReturn("https://tc.example.com/buildConfiguration/Lib_Build/7");

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
        when(build.getStartDate()).thenReturn(new Date(0));
        when(build.getFinishDate()).thenReturn(new Date(0));
        when(build.getRevisions()).thenReturn(List.of());
        stubPlatform(build);
        BuildPromotion promotion = mock(BuildPromotion.class);
        doReturn(List.of(dependency, dependency)).when(promotion).getDependencies();
        when(build.getBuildPromotion()).thenReturn(promotion);

        ProvenanceBuilder builder = new ProvenanceBuilder(server, webLinks, descriptor, parameterFilter);
        InTotoStatement statement = builder.build(build,
                List.of(new ArtifactSubject("app.jar", 1, "deadbeef")), false);

        List<ResolvedDependency> deps =
                statement.predicate().buildDefinition().resolvedDependencies();
        assertEquals(1, deps.size());
        assertEquals("https://tc.example.com/buildConfiguration/Lib_Build/7", deps.get(0).uri());
        assertEquals("Lib_Build #3.2", deps.get(0).name());
    }

    @Test
    void includesRedactedBuildParametersWhenEnabled() {
        SBuildServer server = mock(SBuildServer.class);
        when(server.getFullServerVersion()).thenReturn("TeamCity 2026.1");
        WebLinks webLinks = mock(WebLinks.class);
        when(webLinks.getRootUrlByProjectExternalId(any())).thenReturn("https://tc.example.com");

        SBuild build = mock(SBuild.class);
        when(build.getBuildId()).thenReturn(1L);
        when(build.getBuildTypeExternalId()).thenReturn("Bt");
        when(build.getBranch()).thenReturn(null);
        when(build.getRevisions()).thenReturn(List.of());
        when(build.getStartDate()).thenReturn(new Date(0));
        when(build.getFinishDate()).thenReturn(new Date(0));
        stubPlatform(build);
        when(parameterFilter.safeCustomParameters(build)).thenReturn(Map.of("env.TARGET", "prod"));

        ProvenanceBuilder builder = new ProvenanceBuilder(server, webLinks, descriptor, parameterFilter);
        InTotoStatement statement = builder.build(build,
                List.of(new ArtifactSubject("app.jar", 1, "deadbeef")), true);

        ExternalParameters external = statement.predicate().buildDefinition().externalParameters();
        assertEquals(Map.of("env.TARGET", "prod"), external.customBuildParameters());
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
