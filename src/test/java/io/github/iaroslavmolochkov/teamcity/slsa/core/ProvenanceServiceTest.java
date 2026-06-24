package io.github.iaroslavmolochkov.teamcity.slsa.core;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.client.KmsClientCache;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.persist.ProvenancePublisher;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.ProvenanceBuilder;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.ProvenanceJsonHandler;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.Sha256Handler;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.DsseService;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningServices;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.Validators;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.ConnectionIdService;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.KmsSigningService;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.keys.StaticConnectionKeyHandler;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.keys.StaticKmsClientLoader;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.kms.keys.StaticKmsValidator;
import jetbrains.buildServer.BuildProblemData;
import jetbrains.buildServer.messages.Status;
import jetbrains.buildServer.serverSide.SBuildFeatureDescriptor;
import jetbrains.buildServer.serverSide.SRunningBuild;
import jetbrains.buildServer.serverSide.buildLog.BuildLog;
import jetbrains.buildServer.serverSide.buildLog.MessageAttrs;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ProvenanceServiceTest {

    private ProvenanceService newService() {
        Validators validators = new Validators(List.of(new StaticKmsValidator()));
        ConnectionIdService connectionIdService = new ConnectionIdService(List.of(new StaticConnectionKeyHandler()));
        SigningServices services = new SigningServices(List.of(
                new KmsSigningService(
                        List.of(new StaticKmsClientLoader(mock(KmsClientCache.class), connectionIdService)), new DsseService())));
        return new ProvenanceService(
                validators,
                mock(ArtifactHasher.class),
                mock(ProvenanceBuilder.class),
                new ProvenanceJsonHandler(),
                services,
                mock(ProvenancePublisher.class),
                new Sha256Handler());
    }

    @Test
    void warnsButDoesNotFailForInvalidConfigByDefault() {
        SRunningBuild build = buildWith(Map.of(SlsaParams.SIGNER, SlsaParams.SIGNER_AWS_KMS_STATIC), Status.NORMAL);

        newService().onBuildFinished(build);

        verify(build.getBuildLog()).messageAsync(anyString(), eq(Status.WARNING), any(MessageAttrs.class));
        verify(build, never()).addBuildProblem(any());
    }

    @Test
    void failsBuildWhenOptedIn() {
        SRunningBuild build = buildWith(
                Map.of(SlsaParams.SIGNER, SlsaParams.SIGNER_AWS_KMS_STATIC, SlsaParams.FAIL_BUILD_ON_ERROR, "true"),
                Status.NORMAL);

        newService().onBuildFinished(build);

        verify(build).addBuildProblem(any(BuildProblemData.class));
    }

    @Test
    void skipsUnsuccessfulBuild() {
        SRunningBuild build = buildWith(Map.of(SlsaParams.SIGNER, SlsaParams.SIGNER_AWS_KMS_STATIC), Status.FAILURE);

        newService().onBuildFinished(build);

        verify(build.getBuildLog(), never()).messageAsync(anyString(), any(), any(MessageAttrs.class));
        verify(build, never()).addBuildProblem(any());
    }

    @Test
    void doesNothingWhenFeatureAbsent() {
        SRunningBuild build = mock(SRunningBuild.class);
        when(build.getBuildStatus()).thenReturn(Status.NORMAL);
        when(build.getBuildFeaturesOfType(SlsaParams.FEATURE_TYPE)).thenReturn(List.of());
        when(build.getBuildLog()).thenReturn(mock(BuildLog.class));

        newService().onBuildFinished(build);

        verify(build.getBuildLog(), never()).messageAsync(anyString(), any(), any(MessageAttrs.class));
        verify(build, never()).addBuildProblem(any());
    }

    private static SRunningBuild buildWith(Map<String, String> params, Status status) {
        SBuildFeatureDescriptor feature = mock(SBuildFeatureDescriptor.class);
        when(feature.getParameters()).thenReturn(params);
        SRunningBuild build = mock(SRunningBuild.class);
        when(build.getBuildStatus()).thenReturn(status);
        when(build.getBuildFeaturesOfType(SlsaParams.FEATURE_TYPE)).thenReturn(List.of(feature));
        when(build.getBuildLog()).thenReturn(mock(BuildLog.class));
        return build;
    }
}
