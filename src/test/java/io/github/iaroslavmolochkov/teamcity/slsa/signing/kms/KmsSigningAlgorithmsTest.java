package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KmsSigningAlgorithmsTest {

    @Test
    void supportsOnlyTheNineSha2PrehashSpecs() {
        assertEquals(9, KmsSigningAlgorithms.SUPPORTED.size());
        assertTrue(KmsSigningAlgorithms.SUPPORTED.contains(SigningAlgorithmSpec.ECDSA_SHA_256));
        assertTrue(KmsSigningAlgorithms.SUPPORTED.contains(SigningAlgorithmSpec.RSASSA_PSS_SHA_512));
        assertTrue(KmsSigningAlgorithms.SUPPORTED.contains(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256));
    }

    @Test
    void excludesAlgorithmsTheDigestPathCannotHandle() {
        assertFalse(KmsSigningAlgorithms.SUPPORTED.contains(SigningAlgorithmSpec.SM2_DSA));
        assertFalse(KmsSigningAlgorithms.SUPPORTED.contains(SigningAlgorithmSpec.ML_DSA_SHAKE_256));
        assertFalse(KmsSigningAlgorithms.SUPPORTED.contains(SigningAlgorithmSpec.ED25519_SHA_512));
        assertFalse(KmsSigningAlgorithms.SUPPORTED.contains(SigningAlgorithmSpec.ED25519_PH_SHA_512));
    }

    @Test
    void isSupportedMatchesByWireValue() {
        assertTrue(KmsSigningAlgorithms.isSupported(SigningAlgorithmSpec.ECDSA_SHA_256.toString()));
        assertFalse(KmsSigningAlgorithms.isSupported(SigningAlgorithmSpec.SM2_DSA.toString()));
        assertFalse(KmsSigningAlgorithms.isSupported(null));
        assertFalse(KmsSigningAlgorithms.isSupported("some random string"));
    }

    @Test
    void dropdownValuesEqualTheSupportedSpecs() {
        assertEquals(
                KmsSigningAlgorithms.SUPPORTED.stream().map(SigningAlgorithmSpec::toString).toList(),
                KmsSigningAlgorithms.values());
    }
}
