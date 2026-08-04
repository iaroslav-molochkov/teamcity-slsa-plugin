package io.github.iaroslavmolochkov.slsa.feature;

import io.github.iaroslavmolochkov.slsa.signing.kms.KmsSigningAlgorithms;
import jetbrains.buildServer.controllers.BaseController;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

/** Renders the feature's edit page, injecting the KMS signing algorithms from the AWS SDK enum. */
@Component
public class SlsaEditFeatureController extends BaseController {

    static final String EDIT_PATH = "editSlsaProvenanceFeature.html";
    private static final String JSP = "editSlsaProvenanceFeature.jsp";

    private final String jspPath;

    public SlsaEditFeatureController(PluginDescriptor descriptor, WebControllerManager controllerManager) {
        this.jspPath = descriptor.getPluginResourcesPath(JSP);
        controllerManager.registerController(descriptor.getPluginResourcesPath(EDIT_PATH), this);
    }

    @Override
    @SuppressWarnings("NullableProblems")
    protected ModelAndView doHandle(HttpServletRequest request, HttpServletResponse response) {
        ModelAndView modelAndView = new ModelAndView(jspPath);
        modelAndView.addObject("signingAlgorithms", signingAlgorithms());
        return modelAndView;
    }

    private List<String> signingAlgorithms() {
        return KmsSigningAlgorithms.values();
    }
}
