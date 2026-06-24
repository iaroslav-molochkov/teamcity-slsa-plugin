package io.github.iaroslavmolochkov.teamcity.slsa.signing.server;

import io.github.iaroslavmolochkov.teamcity.slsa.provenance.Sha256Handler;
import jetbrains.buildServer.serverSide.crypt.EncryptUtil;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.StringReader;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;

/** Parses a PEM private key (PKCS#8, PKCS#1 or SEC1) into a {@link ServerKey}, deriving the public key and {@code keyId}. */
@Component
public class ServerKeyParser {

    private final Sha256Handler sha256;

    public ServerKeyParser(Sha256Handler sha256) {
        this.sha256 = sha256;
    }

    /**
     * Parses the stored PEM (unscrambling it first if TeamCity stored it as a {@code secure:} value).
     * Throws {@link InvalidServerKeyException} if the value is not a usable EC or RSA private key.
     */
    public ServerKey parse(String storedPem) {
        String pem = EncryptUtil.isScrambled(storedPem) ? EncryptUtil.unscramble(storedPem) : storedPem;
        PrivateKey privateKey = readPrivateKey(pem);
        PublicKey publicKey = derivePublicKey(privateKey);
        String keyId = "sha256:" + sha256.hex(publicKey.getEncoded());
        return new ServerKey(privateKey, publicKey, signatureAlgorithm(privateKey), keyId);
    }

    private PrivateKey readPrivateKey(String pem) {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object object = parser.readObject();
            if (object == null) {
                throw new InvalidServerKeyException("no PEM private key found");
            }
            PrivateKeyInfo info = switch (object) {
                case PEMKeyPair keyPair -> keyPair.getPrivateKeyInfo();
                case PrivateKeyInfo pkcs8 -> pkcs8;
                default -> throw new InvalidServerKeyException(
                        "unsupported PEM object: " + object.getClass().getSimpleName()
                                + " (encrypted keys are not supported)");
            };
            String algorithm = keyAlgorithm(info.getPrivateKeyAlgorithm().getAlgorithm());
            return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(info.getEncoded()));
        } catch (IOException | GeneralSecurityException e) {
            throw new InvalidServerKeyException("could not read PEM private key", e);
        }
    }

    /** Maps the PKCS#8 algorithm OID to a JCA {@code KeyFactory} name. */
    private String keyAlgorithm(ASN1ObjectIdentifier oid) {
        if (X9ObjectIdentifiers.id_ecPublicKey.equals(oid)) {
            return "EC";
        }
        if (PKCSObjectIdentifiers.rsaEncryption.equals(oid)) {
            return "RSA";
        }
        throw new InvalidServerKeyException("unsupported key algorithm: " + oid);
    }

    private PublicKey derivePublicKey(PrivateKey privateKey) {
        try {
            return switch (privateKey) {
                case ECPrivateKey ec -> deriveEcPublicKey(ec);
                case RSAPrivateCrtKey rsa -> KeyFactory.getInstance("RSA")
                        .generatePublic(new RSAPublicKeySpec(rsa.getModulus(), rsa.getPublicExponent()));
                default -> throw new InvalidServerKeyException(
                        "cannot derive public key for " + privateKey.getAlgorithm() + " key");
            };
        } catch (GeneralSecurityException e) {
            throw new InvalidServerKeyException("could not derive public key", e);
        }
    }

    private PublicKey deriveEcPublicKey(ECPrivateKey ec) throws GeneralSecurityException {
        ECParameterSpec bcSpec = EC5Util.convertSpec(ec.getParams());
        org.bouncycastle.math.ec.ECPoint q =
                new FixedPointCombMultiplier().multiply(bcSpec.getG(), ec.getS()).normalize();
        ECPoint w = new ECPoint(q.getAffineXCoord().toBigInteger(), q.getAffineYCoord().toBigInteger());
        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(w, ec.getParams()));
    }

    private String signatureAlgorithm(PrivateKey privateKey) {
        return switch (privateKey) {
            case ECPrivateKey ec -> ecSignatureAlgorithm(ec);
            case RSAPrivateCrtKey ignored -> "SHA256withRSA";
            default -> throw new InvalidServerKeyException(
                    "unsupported key type: " + privateKey.getAlgorithm());
        };
    }

    private String ecSignatureAlgorithm(ECPrivateKey ec) {
        int fieldSize = ec.getParams()
                .getCurve()
                .getField()
                .getFieldSize();
        if (fieldSize <= 256) {
            return "SHA256withECDSA";
        }
        if (fieldSize <= 384) {
            return "SHA384withECDSA";
        }
        return "SHA512withECDSA";
    }
}
