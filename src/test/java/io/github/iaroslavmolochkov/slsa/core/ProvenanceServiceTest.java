package io.github.iaroslavmolochkov.slsa.core;

import io.github.iaroslavmolochkov.slsa.aws.client.KmsClientCache;
import io.github.iaroslavmolochkov.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.slsa.persist.ProvenancePublisher;
import io.github.iaroslavmolochkov.slsa.provenance.ProvenanceBuilder;
import io.github.iaroslavmolochkov.slsa.provenance.ProvenanceJsonHandler;
import io.github.iaroslavmolochkov.slsa.provenance.Sha256Handler;
import io.github.iaroslavmolochkov.slsa.signing.dsse.DsseService;
import io.github.iaroslavmolochkov.slsa.signing.sigstore.SigstoreBundleService;
import io.github.iaroslavmolochkov.slsa.signing.SigningService;
import io.github.iaroslavmolochkov.slsa.signing.ParameterValidator;
import io.github.iaroslavmolochkov.slsa.signing.kms.AwsKmsConnectionKey;
import io.github.iaroslavmolochkov.slsa.signing.kms.AwsKmsSigningHandler;
import io.github.iaroslavmolochkov.slsa.signing.kms.AwsKmsValidator;
import io.github.iaroslavmolochkov.slsa.signing.kms.credentials.DefaultCredentialsHandler;
import io.github.iaroslavmolochkov.slsa.signing.kms.credentials.StaticCredentialsHandler;
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
        ParameterValidator parameterValidator = new ParameterValidator(List.of(new AwsKmsValidator()));
        SigningService services = new SigningService(List.of(
                new AwsKmsSigningHandler(mock(KmsClientCache.class), new AwsKmsConnectionKey(), new DsseService(),
                        List.of(new DefaultCredentialsHandler(), new StaticCredentialsHandler()))));
        return new ProvenanceService(
                parameterValidator,
                mock(ArtifactHasher.class),
                mock(ProvenanceBuilder.class),
                new ProvenanceJsonHandler(),
                services,
                new SigstoreBundleService(),
                mock(ProvenancePublisher.class),
                new Sha256Handler());
    }

    @Test
    void warnsButDoesNotFailForInvalidConfigByDefault() {
        SRunningBuild build = buildWith(Map.of(SlsaParams.SIGNER, SlsaParams.SIGNER_AWS_KMS), Status.NORMAL);

        newService().onBuildFinished(build);

        verify(build.getBuildLog()).messageAsync(anyString(), eq(Status.WARNING), any(MessageAttrs.class));
        verify(build, never()).addBuildProblem(any());
    }

    @Test
    void failsBuildWhenOptedIn() {
        SRunningBuild build = buildWith(
                Map.of(SlsaParams.SIGNER, SlsaParams.SIGNER_AWS_KMS, SlsaParams.FAIL_BUILD_ON_ERROR, "true"),
                Status.NORMAL);

        newService().onBuildFinished(build);

        verify(build).addBuildProblem(any(BuildProblemData.class));
        verify(build.getBuildLog(), never()).messageAsync(anyString(), any(), any(MessageAttrs.class));
    }

    @Test
    void skipsUnsuccessfulBuild() {
        SRunningBuild build = buildWith(Map.of(SlsaParams.SIGNER, SlsaParams.SIGNER_AWS_KMS), Status.FAILURE);

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
