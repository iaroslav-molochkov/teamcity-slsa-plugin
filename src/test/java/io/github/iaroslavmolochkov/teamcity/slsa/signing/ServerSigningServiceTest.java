package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import jetbrains.buildServer.serverSide.ServerPaths;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.Signature;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ServerSigningServiceTest {

    @Test
    void signsWithLocalKeyAndVerifies(@TempDir File dataDir) throws Exception {
        ServerSigningService service = service(dataDir);

        byte[] payload = "{\"_type\":\"https://in-toto.io/Statement/v1\"}".getBytes(StandardCharsets.UTF_8);
        DsseEnvelope envelope = service.sign(Map.of(), payload);

        assertArrayEquals(payload, Base64.getDecoder().decode(envelope.payload()));
        assertEquals(service.keyId(), envelope.signatures().get(0).keyid());

        byte[] pae = Pae.encode(DsseEnvelope.IN_TOTO_PAYLOAD_TYPE, payload);
        byte[] sig = Base64.getDecoder().decode(envelope.signatures().get(0).sig());
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(service.publicKey());
        verifier.update(pae);
        assertTrue(verifier.verify(sig));
    }

    @Test
    void persistsKeyAcrossInstances(@TempDir File dataDir) {
        assertEquals(service(dataDir).keyId(), service(dataDir).keyId());
    }

    @Test
    void privateKeyIsOwnerOnlyOnPosix(@TempDir File dataDir) throws Exception {
        service(dataDir).keyId(); // generate
        Path key = new File(new File(dataDir, "slsa"), "server-signing.key").toPath();
        assumeTrue(key.getFileSystem().supportedFileAttributeViews().contains("posix"));
        assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(key));
    }

    @Test
    void corruptKeyRaisesKeyInitializationException(@TempDir File dataDir) throws Exception {
        File slsaDir = new File(dataDir, "slsa");
        Files.createDirectories(slsaDir.toPath());
        Files.writeString(new File(slsaDir, "server-signing.key").toPath(), "not a key");
        Files.writeString(new File(slsaDir, "server-signing.pub.pem").toPath(), "not a pem");

        assertThrows(KeyInitializationException.class, () -> service(dataDir).keyId());
    }

    private static ServerSigningService service(File dataDir) {
        ServerPaths serverPaths = mock(ServerPaths.class);
        when(serverPaths.getPluginDataDirectory()).thenReturn(dataDir);
        return new ServerSigningService(serverPaths);
    }
}
