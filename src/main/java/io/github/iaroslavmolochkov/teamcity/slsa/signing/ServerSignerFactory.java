package io.github.iaroslavmolochkov.teamcity.slsa.signing;

import com.intellij.openapi.diagnostic.Logger;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SignerConfig;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.Sha256;
import jetbrains.buildServer.log.Loggers;
import jetbrains.buildServer.serverSide.ServerPaths;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Creates {@link Signer}s backed by a local ECDSA P-256 key — the zero-dependency "tick the box"
 * backend. The key pair is generated once and persisted under the plugin data directory; the public
 * key (written next to it as PEM) is what verifiers use. Weaker than KMS (the private key lives on
 * the server's disk), but needs no configuration.
 */
@Component
public class ServerSignerFactory implements SignerFactory {

    private static final Logger LOG = Loggers.SERVER;
    private static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";

    private final File keyFile;
    private final File publicKeyPemFile;

    private KeyPair keyPair;
    private String keyId;

    public ServerSignerFactory(@NotNull ServerPaths serverPaths) {
        File dir = new File(serverPaths.getPluginDataDirectory(), "slsa");
        keyFile = new File(dir, "server-signing.key");
        publicKeyPemFile = new File(dir, "server-signing.pub.pem");
    }

    @NotNull
    @Override
    public String signerId() {
        return SlsaParams.SIGNER_SERVER;
    }

    @NotNull
    @Override
    public Signer create(@NotNull SignerConfig config) {
        // The server config is empty; the key material is the factory's own state.
        return this::sign;
    }

    @NotNull
    private synchronized DsseEnvelope sign(@NotNull byte[] payload) {
        ensureKey();
        byte[] pae = Pae.encode(DsseEnvelope.IN_TOTO_PAYLOAD_TYPE, payload);
        try {
            Signature signer = Signature.getInstance(SIGNATURE_ALGORITHM);
            signer.initSign(keyPair.getPrivate());
            signer.update(pae);
            return DsseEnvelope.of(payload, keyId, signer.sign());
        } catch (Exception e) {
            throw new SigningException("Server-side signing failed", e);
        }
    }

    /** The public key verifiers use to check signatures produced by this signer. */
    @NotNull
    public synchronized PublicKey publicKey() {
        ensureKey();
        return keyPair.getPublic();
    }

    /** The DSSE {@code keyid} embedded in envelopes from this signer. */
    @NotNull
    public synchronized String keyId() {
        ensureKey();
        return keyId;
    }

    private void ensureKey() {
        if (keyPair != null) {
            return;
        }
        try {
            keyPair = keyFile.isFile() ? load() : generateAndPersist();
            keyId = "sha256:" + Sha256.hex(keyPair.getPublic().getEncoded());
        } catch (Exception e) {
            throw new KeyInitializationException("Failed to initialize the server signing key at " + keyFile, e);
        }
    }

    private KeyPair load() throws Exception {
        byte[] privateDer = Files.readAllBytes(keyFile.toPath());
        byte[] publicDer = pemToDer(Files.readString(publicKeyPemFile.toPath(), StandardCharsets.UTF_8));
        KeyFactory factory = KeyFactory.getInstance("EC");
        PrivateKey privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(privateDer));
        PublicKey publicKey = factory.generatePublic(new X509EncodedKeySpec(publicDer));
        return new KeyPair(publicKey, privateKey);
    }

    private KeyPair generateAndPersist() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair generated = generator.generateKeyPair();

        Files.createDirectories(keyFile.getParentFile().toPath());
        writeOwnerOnly(keyFile.toPath(), generated.getPrivate().getEncoded());
        // The public key is meant to be shared, so default permissions are fine.
        Files.writeString(publicKeyPemFile.toPath(), derToPem(generated.getPublic().getEncoded()), StandardCharsets.UTF_8);

        LOG.info("SLSA: generated server signing key at " + keyFile + "; public key: " + publicKeyPemFile);
        return generated;
    }

    /**
     * Writes the private key readable/writable only by the owner. On POSIX the permissions are applied
     * <em>at file creation</em>, so the key is never momentarily world-readable; elsewhere (e.g. Windows)
     * it falls back to a best-effort {@link File} chmod after writing.
     */
    @SuppressWarnings("ResultOfMethodCallIgnored")
    private static void writeOwnerOnly(@NotNull Path path, @NotNull byte[] content) throws IOException {
        Files.deleteIfExists(path);
        if (path.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            Files.createFile(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
            Files.write(path, content);
        } else {
            Files.write(path, content);
            File file = path.toFile();
            file.setReadable(false, false);
            file.setReadable(true, true);
            file.setWritable(false, false);
            file.setWritable(true, true);
        }
    }

    @NotNull
    private static String derToPem(@NotNull byte[] der) {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der);
        return "-----BEGIN PUBLIC KEY-----\n" + base64 + "\n-----END PUBLIC KEY-----\n";
    }

    @NotNull
    private static byte[] pemToDer(@NotNull String pem) {
        String base64 = pem.replaceAll("-----BEGIN [^-]+-----", "")
                .replaceAll("-----END [^-]+-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(base64);
    }
}
