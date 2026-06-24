package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import software.amazon.awssdk.services.kms.KmsClient;

/**
 * Builds (or fetches from cache) the KMS client for one AWS credentials mode. Selected by
 * {@link #type()}; {@link AbstractKmsClientLoader} provides the cache lookup and the shared client build.
 */
public interface KmsClientLoader {

    SignerType type();

    KmsClient load(SigningContext context);
}
