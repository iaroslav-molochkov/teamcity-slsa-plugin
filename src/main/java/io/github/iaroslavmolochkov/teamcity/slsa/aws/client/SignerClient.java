package io.github.iaroslavmolochkov.teamcity.slsa.aws.client;

import com.intellij.openapi.diagnostic.Logger;
import jetbrains.buildServer.log.Loggers;
import org.jetbrains.annotations.NotNull;
import software.amazon.awssdk.services.kms.KmsClient;

import java.util.ArrayList;
import java.util.List;

/**
 * Owns a configured {@link KmsClient} and the resources the SDK won't close itself: the shared HTTP
 * client, and (for assume-role) the STS client + credentials provider. {@link #close()} releases them
 * in reverse order, so the shared HTTP client — added first — is released last.
 */
public final class SignerClient implements AutoCloseable {

    private static final Logger LOG = Loggers.SERVER;

    private final KmsClient kms;
    private final List<AutoCloseable> closeables;

    public SignerClient(@NotNull KmsClient kms, @NotNull List<AutoCloseable> closeables) {
        this.kms = kms;
        this.closeables = new ArrayList<>(closeables);
    }

    @NotNull
    public KmsClient kms() {
        return kms;
    }

    @Override
    public void close() {
        closeQuietly(kms);
        for (int i = closeables.size() - 1; i >= 0; i--) {
            closeQuietly(closeables.get(i));
        }
    }

    private static void closeQuietly(@NotNull AutoCloseable closeable) {
        try {
            closeable.close();
        } catch (Exception e) {
            LOG.warnAndDebugDetails("SLSA: failed to close " + closeable.getClass().getSimpleName(), e);
        }
    }
}
