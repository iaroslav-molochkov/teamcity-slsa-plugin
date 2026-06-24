package io.github.iaroslavmolochkov.teamcity.slsa.feature;

import jetbrains.buildServer.controllers.BaseController;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.ModelAndView;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.List;

/**
 * Renders the build feature's edit page. It injects the KMS signing algorithms straight from the AWS SDK
 * enum so the dropdown can never drift from what the SDK actually supports — when the SDK adds an
 * algorithm, it appears here on the next upgrade with no JSP edit.
 */
@Component
public class SlsaEditFeatureController extends BaseController {

    /** Edit URL the build feature points at; backed by this controller, not the JSP directly. */
    static final String EDIT_PATH = "editSlsaProvenanceFeature.html";
    private static final String JSP = "editSlsaProvenanceFeature.jsp";

    private final String jspPath;

    public SlsaEditFeatureController(PluginDescriptor descriptor, WebControllerManager controllerManager) {
        this.jspPath = descriptor.getPluginResourcesPath(JSP);
        controllerManager.registerController(descriptor.getPluginResourcesPath(EDIT_PATH), this);
    }

    @Override
    protected ModelAndView doHandle(HttpServletRequest request, HttpServletResponse response) {
        ModelAndView modelAndView = new ModelAndView(jspPath);
        modelAndView.addObject("signingAlgorithms", signingAlgorithms());
        return modelAndView;
    }

    private List<String> signingAlgorithms() {
        return Arrays.stream(SigningAlgorithmSpec.values())
                .filter(spec -> spec != SigningAlgorithmSpec.UNKNOWN_TO_SDK_VERSION)
                .map(SigningAlgorithmSpec::toString)
                .toList();
    }
}
