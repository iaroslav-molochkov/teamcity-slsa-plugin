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

class ServerSignerFactoryTest {

    @Test
    void validatorIsAlwaysValid() {
        assertTrue(new ServerValidator().validate(Map.of()).isEmpty());
    }

    @Test
    void mapsToServerConfig() {
        assertEquals(ServerSignerConfig.INSTANCE, new ServerConfigMapper().map(Map.of()));
    }

    @Test
    void signsWithLocalKeyAndVerifies(@TempDir File dataDir) throws Exception {
        ServerSignerFactory factory = factory(dataDir);
        byte[] payload = "{\"_type\":\"https://in-toto.io/Statement/v1\"}".getBytes(StandardCharsets.UTF_8);
        DsseEnvelope envelope = factory.create(ServerSignerConfig.INSTANCE).sign(payload);

        assertArrayEquals(payload, Base64.getDecoder().decode(envelope.payload()));
        assertEquals(factory.keyId(), envelope.signatures().get(0).keyid());

        byte[] pae = Pae.encode(DsseEnvelope.IN_TOTO_PAYLOAD_TYPE, payload);
        byte[] sig = Base64.getDecoder().decode(envelope.signatures().get(0).sig());
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(factory.publicKey());
        verifier.update(pae);
        assertTrue(verifier.verify(sig));
    }

    @Test
    void persistsKeyAcrossInstances(@TempDir File dataDir) {
        assertEquals(factory(dataDir).keyId(), factory(dataDir).keyId());
    }

    @Test
    void privateKeyIsOwnerOnlyOnPosix(@TempDir File dataDir) throws Exception {
        factory(dataDir).keyId(); // generate
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

        assertThrows(KeyInitializationException.class, () -> factory(dataDir).keyId());
    }

    private static ServerSignerFactory factory(File dataDir) {
        ServerPaths serverPaths = mock(ServerPaths.class);
        when(serverPaths.getPluginDataDirectory()).thenReturn(dataDir);
        return new ServerSignerFactory(serverPaths);
    }
}
