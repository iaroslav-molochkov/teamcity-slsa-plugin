package io.github.iaroslavmolochkov.teamcity.slsa.signing.kms;

import io.github.iaroslavmolochkov.teamcity.slsa.signing.SignerType;
import io.github.iaroslavmolochkov.teamcity.slsa.signing.SigningContext;
import software.amazon.awssdk.services.kms.KmsClient;

/** Builds or fetches from cache the KMS client for one AWS credentials mode. */
public interface KmsClientLoader {

    SignerType type();

    KmsClient load(SigningContext context);
}
