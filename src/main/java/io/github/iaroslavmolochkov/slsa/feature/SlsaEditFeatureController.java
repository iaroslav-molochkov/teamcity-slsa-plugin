package io.github.iaroslavmolochkov.slsa.feature;

import io.github.iaroslavmolochkov.slsa.signing.kms.KmsSigningAlgorithms;
import io.github.iaroslavmolochkov.slsa.signing.server.ServerKeyStore;
import jetbrains.buildServer.controllers.BaseController;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

/** Renders the feature's edit page, injecting the KMS signing algorithms and the server key store names. */
@Component
public class SlsaEditFeatureController extends BaseController {

    static final String EDIT_PATH = "editSlsaProvenanceFeature.html";
    private static final String JSP = "editSlsaProvenanceFeature.jsp";

    private final String jspPath;
    private final ServerKeyStore keyStore;

    public SlsaEditFeatureController(PluginDescriptor descriptor, WebControllerManager controllerManager,
                                     ServerKeyStore keyStore) {
        this.jspPath = descriptor.getPluginResourcesPath(JSP);
        this.keyStore = keyStore;
        controllerManager.registerController(descriptor.getPluginResourcesPath(EDIT_PATH), this);
    }

    @Override
    @SuppressWarnings("NullableProblems")
    protected ModelAndView doHandle(HttpServletRequest request, HttpServletResponse response) {
        ModelAndView modelAndView = new ModelAndView(jspPath);
        modelAndView.addObject("signingAlgorithms", signingAlgorithms());
        modelAndView.addObject("serverKeyNames", keyStore.listNames());
        return modelAndView;
    }

    private List<String> signingAlgorithms() {
        return KmsSigningAlgorithms.values();
    }
}
