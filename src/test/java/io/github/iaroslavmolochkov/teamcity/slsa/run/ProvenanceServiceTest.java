package io.github.iaroslavmolochkov.teamcity.slsa.run;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.client.KmsClientCache;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.BaseCredentialsRegistry;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.CredentialsResolutions;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.DefaultCredentials;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.DirectResolution;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.persist.ProvenancePublisher;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.ProvenanceBuilder;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.ConfigMappers;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.KmsConfigMapper;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.KmsSignerFactory;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.KmsValidator;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerFactories;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.Validators;
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
        BaseCredentialsRegistry bases = new BaseCredentialsRegistry(List.of(new DefaultCredentials()));
        CredentialsResolutions resolutions = new CredentialsResolutions(List.of(new DirectResolution(bases)));
        Validators validators = new Validators(List.of(new KmsValidator(bases, resolutions)));
        ConfigMappers configMappers = new ConfigMappers(List.of(new KmsConfigMapper(bases, resolutions)), validators);
        SignerFactories factories = new SignerFactories(List.of(new KmsSignerFactory(mock(KmsClientCache.class))));
        return new ProvenanceService(
                mock(EventDispatcher.class),
                mock(ArtifactHasher.class),
                mock(ProvenanceBuilder.class),
                configMappers,
                factories,
                mock(ProvenancePublisher.class));
    }

    @Test
    void reportsBuildProblemForInvalidConfig() {
        SBuildFeatureDescriptor feature = mock(SBuildFeatureDescriptor.class);
        // aws-kms selected but region/key/algorithm missing -> invalid
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
