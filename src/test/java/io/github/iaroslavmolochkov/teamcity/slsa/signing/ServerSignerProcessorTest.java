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
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ServerSignerProcessorTest {

    @Test
    void validateIsAlwaysEmpty(@TempDir File dataDir) {
        assertTrue(processor(dataDir).validate(Map.of()).isEmpty());
    }

    @Test
    void processReturnsTheSingletonItself(@TempDir File dataDir) {
        ServerSignerProcessor processor = processor(dataDir);
        Signer signer = processor.process(Map.of()).value();
        assertSame(processor, signer, "server processor is its own signer");
        assertEquals(SignerType.SERVER, signer.type());
    }

    @Test
    void signsWithLocalKeyAndVerifies(@TempDir File dataDir) throws Exception {
        ServerSignerProcessor processor = processor(dataDir);
        Signer signer = processor.process(Map.of()).value();

        byte[] payload = "{\"_type\":\"https://in-toto.io/Statement/v1\"}".getBytes(StandardCharsets.UTF_8);
        DsseEnvelope envelope = signer.sign(payload);

        assertArrayEquals(payload, Base64.getDecoder().decode(envelope.payload()));
        assertEquals(processor.keyId(), envelope.signatures().get(0).keyid());

        byte[] pae = Pae.encode(DsseEnvelope.IN_TOTO_PAYLOAD_TYPE, payload);
        byte[] sig = Base64.getDecoder().decode(envelope.signatures().get(0).sig());
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(processor.publicKey());
        verifier.update(pae);
        assertTrue(verifier.verify(sig));
    }

    @Test
    void persistsKeyAcrossInstances(@TempDir File dataDir) {
        assertEquals(processor(dataDir).keyId(), processor(dataDir).keyId());
    }

    @Test
    void privateKeyIsOwnerOnlyOnPosix(@TempDir File dataDir) throws Exception {
        processor(dataDir).keyId(); // generate
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

        assertThrows(KeyInitializationException.class, () -> processor(dataDir).keyId());
    }

    private static ServerSignerProcessor processor(File dataDir) {
        ServerPaths serverPaths = mock(ServerPaths.class);
        when(serverPaths.getPluginDataDirectory()).thenReturn(dataDir);
        return new ServerSignerProcessor(serverPaths);
    }
}
