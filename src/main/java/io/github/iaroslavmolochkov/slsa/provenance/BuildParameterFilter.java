package io.github.iaroslavmolochkov.slsa.provenance;

import com.intellij.openapi.diagnostic.Logger;
import jetbrains.buildServer.log.Loggers;
import jetbrains.buildServer.serverSide.BuildTypeNotFoundException;
import jetbrains.buildServer.serverSide.ControlDescription;
import jetbrains.buildServer.serverSide.Parameter;
import jetbrains.buildServer.serverSide.SBuild;
import jetbrains.buildServer.serverSide.SBuildServer;
import jetbrains.buildServer.serverSide.parameters.types.PasswordsProvider;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/** Selects the requester-supplied custom build parameters that are safe to publish, dropping declared secrets. */
@Component
public class BuildParameterFilter {

    private static final Logger log = Loggers.SERVER;

    private static final String PASSWORD_TYPE = "password";
    private static final String SECURE_PREFIX = "secure:";

    private final SBuildServer server;

    public BuildParameterFilter(SBuildServer server) {
        this.server = server;
    }

    public Map<String, String> safeCustomParameters(SBuild build) {
        Map<String, String> custom = build.getBuildPromotion().getCustomParameters();

        if (custom.isEmpty()) {
            return Map.of();
        }

        Set<String> secrets = secretNames(build);
        Map<String, String> safe = new HashMap<>();

        for (Map.Entry<String, String> parameter : custom.entrySet()) {
            String name = parameter.getKey();
            if (!name.startsWith(SECURE_PREFIX) && !secrets.contains(name)) {
                safe.put(name, parameter.getValue());
            }
        }

        return safe;
    }

    private Set<String> secretNames(SBuild build) {
        Set<String> names = new HashSet<>();

        for (PasswordsProvider provider : server.getExtensions(PasswordsProvider.class)) {
            for (Parameter parameter : provider.getPasswordParameters(build)) {
                names.add(parameter.getName());
            }
        }

        try {
            for (Parameter parameter : build.getBuildPromotion().getBuildSettings().getParametersCollection()) {
                ControlDescription control = parameter.getControlDescription();
                if (control != null && PASSWORD_TYPE.equals(control.getParameterType())) {
                    names.add(parameter.getName());
                }
            }
        } catch (BuildTypeNotFoundException e) {
            log.debug("SLSA: build configuration for " + build.getBuildId()
                    + " is gone; redacting build parameters via password providers only");
        }

        return names;
    }
}
