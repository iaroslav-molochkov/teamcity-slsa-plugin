package io.github.iaroslavmolochkov.slsa.core;

import io.github.iaroslavmolochkov.slsa.aws.client.KmsClientCache;
import io.github.iaroslavmolochkov.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.slsa.persist.ProvenancePublisher;
import io.github.iaroslavmolochkov.slsa.persist.ProvenancePublishingException;
import io.github.iaroslavmolochkov.slsa.provenance.ArtifactSubject;
import io.github.iaroslavmolochkov.slsa.provenance.ProvenanceBuilder;
import io.github.iaroslavmolochkov.slsa.provenance.ProvenanceJsonHandler;
import io.github.iaroslavmolochkov.slsa.provenance.Sha256Handler;
import io.github.iaroslavmolochkov.slsa.provenance.intoto.InTotoStatement;
import io.github.iaroslavmolochkov.slsa.provenance.slsa.RunDetails;
import io.github.iaroslavmolochkov.slsa.provenance.slsa.SlsaBuilder;
import io.github.iaroslavmolochkov.slsa.provenance.slsa.SlsaPredicate;
import io.github.iaroslavmolochkov.slsa.signing.SigningContext;
import io.github.iaroslavmolochkov.slsa.signing.dsse.DsseService;
import io.github.iaroslavmolochkov.slsa.signing.dsse.DsseEnvelope;
import io.github.iaroslavmolochkov.slsa.signing.dsse.DsseSignature;
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

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
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

    @Test
    void warnsWhenPublicationFailsByDefault() {
        ProvenancePublisher publisher = failingPublisher();
        SRunningBuild build = buildWith(Map.of(SlsaParams.SIGNER, SlsaParams.SIGNER_SERVER), Status.NORMAL);

        serviceThatReachesPublication(publisher).onBuildFinished(build);

        verify(build.getBuildLog()).messageAsync(contains("publication failed"), eq(Status.WARNING),
                any(MessageAttrs.class));
        verify(build, never()).addBuildProblem(any());
    }

    @Test
    void failsBuildWhenPublicationFailsAndFailureIsEnabled() {
        ProvenancePublisher publisher = failingPublisher();
        SRunningBuild build = buildWith(
                Map.of(SlsaParams.SIGNER, SlsaParams.SIGNER_SERVER, SlsaParams.FAIL_BUILD_ON_ERROR, "true"),
                Status.NORMAL);

        serviceThatReachesPublication(publisher).onBuildFinished(build);

        verify(build).addBuildProblem(any(BuildProblemData.class));
        verify(build.getBuildLog(), never()).messageAsync(anyString(), any(), any(MessageAttrs.class));
    }

    private static ProvenanceService serviceThatReachesPublication(ProvenancePublisher publisher) {
        ParameterValidator parameterValidator = mock(ParameterValidator.class);
        when(parameterValidator.validate(any(SigningContext.class))).thenReturn(List.of());

        ArtifactHasher hasher = mock(ArtifactHasher.class);
        when(hasher.hash(any())).thenReturn(List.of(new ArtifactSubject("artifact.txt", 3, "abc")));

        ProvenanceBuilder provenanceBuilder = mock(ProvenanceBuilder.class);
        InTotoStatement statement = new InTotoStatement(
                InTotoStatement.TYPE,
                List.of(),
                InTotoStatement.SLSA_PREDICATE_TYPE,
                new SlsaPredicate(null, new RunDetails(new SlsaBuilder("https://teamcity.example", Map.of()), null)));
        when(provenanceBuilder.build(any(), anyList(), anyBoolean())).thenReturn(statement);

        SigningService signingService = mock(SigningService.class);
        when(signingService.sign(any(SigningContext.class), any(byte[].class)))
                .thenReturn(new DsseEnvelope("e30=", DsseEnvelope.IN_TOTO_PAYLOAD_TYPE,
                        List.of(new DsseSignature("key-id", "c2ln"))));

        return new ProvenanceService(
                parameterValidator,
                hasher,
                provenanceBuilder,
                new ProvenanceJsonHandler(),
                signingService,
                new SigstoreBundleService(),
                publisher,
                new Sha256Handler());
    }

    private static ProvenancePublisher failingPublisher() {
        ProvenancePublisher publisher = mock(ProvenancePublisher.class);
        doThrow(new ProvenancePublishingException("publication failed", new IOException("disk full")))
                .when(publisher)
                .publish(any(), any(byte[].class), any());
        return publisher;
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
