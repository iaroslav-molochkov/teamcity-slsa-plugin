package io.github.iaroslavmolochkov.slsa.aws.client;

import com.intellij.openapi.diagnostic.Logger;
import jetbrains.buildServer.log.Loggers;
import software.amazon.awssdk.services.kms.KmsClient;

import java.util.ArrayList;
import java.util.List;

/** A {@link KmsClient} plus the resources the SDK won't close itself; {@link #close()} releases them in reverse order. */
public final class SignerClient implements AutoCloseable {

    private static final Logger log = Loggers.SERVER;

    private final KmsClient kms;
    private final List<AutoCloseable> closeables;

    public SignerClient(KmsClient kms, List<AutoCloseable> closeables) {
        this.kms = kms;
        this.closeables = new ArrayList<>(closeables);
    }

    public KmsClient kms() {
        return kms;
    }

    @Override
    public void close() {
        close(kms);
        for (int i = closeables.size() - 1; i >= 0; i--) {
            close(closeables.get(i));
        }
    }

    private void close(AutoCloseable closeable) {
        try {
            closeable.close();
        } catch (Exception e) {
            log.warnAndDebugDetails("SLSA: failed to close " + closeable.getClass().getSimpleName(), e);
        }
    }
}
