package io.github.iaroslavmolochkov.teamcity.slsa.run;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.client.KmsClientCache;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.AssumeRoleAwsCredentials;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.AwsCredentialsRegistry;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.DefaultAwsCredentials;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.StaticAwsCredentials;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.persist.ProvenancePublisher;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.ProvenanceBuilder;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.KmsConfigMapper;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.KmsSignerResolver;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.KmsValidator;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerHandler;
import jetbrains.buildServer.BuildProblemData;
import jetbrains.buildServer.serverSide.BuildServerListener;
import jetbrains.buildServer.serverSide.SBuild;
import jetbrains.buildServer.serverSide.SBuildFeatureDescriptor;
import jetbrains.buildServer.util.EventDispatcher;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ProvenanceServiceTest {

    @SuppressWarnings("unchecked")
    private ProvenanceService newService() {
        AwsCredentialsRegistry credentials = new AwsCredentialsRegistry(
                List.of(new DefaultAwsCredentials(), new StaticAwsCredentials(), new AssumeRoleAwsCredentials()));
        KmsSignerResolver kms = new KmsSignerResolver(
                new KmsValidator(credentials), new KmsConfigMapper(), mock(KmsClientCache.class));
        SignerHandler handler = new SignerHandler(List.of(kms));
        return new ProvenanceService(
                mock(EventDispatcher.class),
                mock(ArtifactHasher.class),
                mock(ProvenanceBuilder.class),
                handler,
                mock(ProvenancePublisher.class));
    }

    @Test
    void reportsBuildProblemForInvalidConfig() {
        SBuildFeatureDescriptor feature = mock(SBuildFeatureDescriptor.class);
        // aws-kms selected but region/key/algorithm/credentials missing -> invalid
        when(feature.getParameters()).thenReturn(Map.of(SlsaParams.SIGNER, SlsaParams.SIGNER_AWS_KMS));

        SBuild build = mock(SBuild.class);
        when(build.getBuildFeaturesOfType(SlsaParams.FEATURE_TYPE)).thenReturn(List.of(feature));

        newService().onBuildFinished(build);

        verify(build).addBuildProblem(any(BuildProblemData.class));
    }

    @Test
    void noProblemWhenFeatureAbsent() {
        SBuild build = mock(SBuild.class);
        when(build.getBuildFeaturesOfType(SlsaParams.FEATURE_TYPE)).thenReturn(List.of());

        newService().onBuildFinished(build);

        verify(build, never()).addBuildProblem(any());
    }
}
