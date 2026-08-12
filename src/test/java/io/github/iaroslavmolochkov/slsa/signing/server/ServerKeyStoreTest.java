package io.github.iaroslavmolochkov.slsa.signing.server;

import jetbrains.buildServer.serverSide.ServerPaths;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ServerKeyStoreTest {

    @Test
    void createsKeysDirectoryOnStartup(@TempDir Path dir) {
        store(dir);
        assertTrue(Files.isDirectory(keysDir(dir)));
    }

    @Test
    void listsMatchingFileNamesSorted(@TempDir Path dir) throws Exception {
        ServerKeyStore store = store(dir);
        Files.writeString(keysDir(dir).resolve("b.pem"), "b");
        Files.writeString(keysDir(dir).resolve("a.pem"), "a");
        Files.writeString(keysDir(dir).resolve("bad name.pem"), "skipped");
        Files.createDirectory(keysDir(dir).resolve("subdir"));

        assertEquals(java.util.List.of("a.pem", "b.pem"), store.listNames());
    }

    @Test
    void readsKeyContentByName(@TempDir Path dir) throws Exception {
        ServerKeyStore store = store(dir);
        Files.writeString(keysDir(dir).resolve("key.pem"), "pem-content");

        assertEquals("pem-content", store.read("key.pem"));
    }

    @Test
    void rejectsMissingKey(@TempDir Path dir) {
        assertThrows(InvalidServerKeyException.class, () -> store(dir).read("absent.pem"));
    }

    @Test
    void rejectsTraversalAndInvalidNames(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("outside.pem"), "secret");
        ServerKeyStore store = store(dir);

        assertThrows(InvalidServerKeyException.class, () -> store.read("../../outside.pem"));
        assertThrows(InvalidServerKeyException.class, () -> store.read("/etc/passwd"));
        assertThrows(InvalidServerKeyException.class, () -> store.read("a/b.pem"));
        assertThrows(InvalidServerKeyException.class, () -> store.read(null));
    }

    private static ServerKeyStore store(Path dir) {
        return new ServerKeyStore(new ServerPaths(dir.toFile()));
    }

    private static Path keysDir(Path dir) {
        return dir.resolve("system").resolve("pluginData").resolve("slsa").resolve("keys");
    }
}
