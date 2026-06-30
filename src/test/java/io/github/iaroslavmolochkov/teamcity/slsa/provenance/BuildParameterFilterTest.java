package io.github.iaroslavmolochkov.teamcity.slsa.provenance;

import jetbrains.buildServer.serverSide.BuildPromotion;
import jetbrains.buildServer.serverSide.ControlDescription;
import jetbrains.buildServer.serverSide.Parameter;
import jetbrains.buildServer.serverSide.ReadOnlyBuildSettings;
import jetbrains.buildServer.serverSide.SBuild;
import jetbrains.buildServer.serverSide.SBuildServer;
import jetbrains.buildServer.serverSide.parameters.types.PasswordsProvider;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class BuildParameterFilterTest {

    private final SBuildServer server = mock(SBuildServer.class);
    private final BuildParameterFilter filter = new BuildParameterFilter(server);

    @Test
    void dropsDeclaredSecretsButKeepsPlainParameters() {
        SBuild build = mock(SBuild.class);
        BuildPromotion promotion = mock(BuildPromotion.class);
        when(build.getBuildPromotion()).thenReturn(promotion);
        when(promotion.getCustomParameters()).thenReturn(Map.of(
                "env.TARGET", "prod",
                "pwd", "s3cr3t",
                "secure:token", "abc",
                "providerSecret", "xyz"));

        Parameter passwordParam = param("pwd", "password");
        Parameter plainParam = param("env.TARGET", "text");
        Parameter providerParam = param("providerSecret", "text");

        ReadOnlyBuildSettings settings = mock(ReadOnlyBuildSettings.class);
        when(promotion.getBuildSettings()).thenReturn(settings);
        when(settings.getParametersCollection()).thenReturn(List.of(passwordParam, plainParam));

        PasswordsProvider provider = mock(PasswordsProvider.class);
        when(provider.getPasswordParameters(build)).thenReturn(List.of(providerParam));
        when(server.getExtensions(PasswordsProvider.class)).thenReturn(List.of(provider));

        Map<String, String> safe = filter.safeCustomParameters(build);

        assertEquals(Map.of("env.TARGET", "prod"), safe);
        assertFalse(safe.containsKey("pwd"), "password-typed parameter dropped");
        assertFalse(safe.containsKey("secure:token"), "secure: prefixed parameter dropped");
        assertFalse(safe.containsKey("providerSecret"), "PasswordsProvider-named parameter dropped");
    }

    @Test
    void emptyWhenNoCustomParameters() {
        SBuild build = mock(SBuild.class);
        BuildPromotion promotion = mock(BuildPromotion.class);
        when(build.getBuildPromotion()).thenReturn(promotion);
        when(promotion.getCustomParameters()).thenReturn(Map.of());

        assertTrue(filter.safeCustomParameters(build).isEmpty());
    }

    private static Parameter param(String name, String type) {
        Parameter parameter = mock(Parameter.class);
        when(parameter.getName()).thenReturn(name);
        ControlDescription control = mock(ControlDescription.class);
        when(control.getParameterType()).thenReturn(type);
        when(parameter.getControlDescription()).thenReturn(control);
        return parameter;
    }
}
