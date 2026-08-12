package io.github.iaroslavmolochkov.slsa.signing.server;

import com.intellij.openapi.diagnostic.Logger;
import jetbrains.buildServer.log.Loggers;
import jetbrains.buildServer.serverSide.ServerPaths;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/** Server-admin-managed key store: PEM private keys under {@code system/pluginData/slsa/keys}, referenced by file name. */
@Component
public class ServerKeyStore {

    private static final Logger log = Loggers.SERVER;

    private static final Pattern NAME = Pattern.compile("[A-Za-z0-9._-]+");

    private final Path keysDir;

    public ServerKeyStore(ServerPaths serverPaths) {
        keysDir = serverPaths.getPluginDataDirectory()
                .toPath()
                .toAbsolutePath()
                .normalize()
                .resolve("slsa")
                .resolve("keys");

        try {
            Files.createDirectories(keysDir);
        } catch (IOException e) {
            log.warn("SLSA: could not create the server key store directory " + keysDir, e);
        }
    }

    public List<String> listNames() {
        if (!Files.isDirectory(keysDir)) {
            return List.of();
        }

        try (Stream<Path> files = Files.list(keysDir)) {
            return files.filter(Files::isRegularFile)
                    .map(file -> file.getFileName().toString())
                    .filter(name -> NAME.matcher(name).matches())
                    .sorted()
                    .toList();
        } catch (IOException e) {
            log.warn("SLSA: could not list the server key store directory " + keysDir, e);
            return List.of();
        }
    }

    public String read(String name) {
        try {
            return Files.readString(resolve(name));
        } catch (IOException e) {
            throw new InvalidServerKeyException("no readable key named " + name + " in the server key store", e);
        }
    }

    private Path resolve(String name) {
        if (name == null || !NAME.matcher(name).matches()) {
            throw new InvalidServerKeyException("invalid key name: " + name);
        }

        Path path = keysDir.resolve(name).normalize();

        if (!path.getParent().equals(keysDir)) {
            throw new InvalidServerKeyException("invalid key name: " + name);
        }

        return path;
    }
}
