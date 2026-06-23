package io.github.iaroslavmolochkov.teamcity.slsa.aws;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.AssumeRoleSpec;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.AwsCredentialsType;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.AwsKeys;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.Sha256;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.nio.charset.StandardCharsets;

import static java.util.Objects.requireNonNullElse;

/**
 * Validated, typed configuration for the AWS KMS signer. Required fields are non-null by construction
 * (the {@code KmsConfigMapper} guarantees it). {@code keys} is present iff {@code credentialsType} is
 * {@code STATIC}, and {@code assumeRole} iff it is {@code ASSUME_ROLE}.
 */
public record KmsSignerConfig(
        @NotNull String region,
        @NotNull String kmsKeyId,
        @NotNull SigningAlgorithmSpec algorithm,
        @NotNull AwsCredentialsType credentialsType,
        @Nullable AwsKeys keys,
        @Nullable AssumeRoleSpec assumeRole,
        @Nullable String stsEndpoint) {

    /**
     * A stable hash over the connection-relevant fields (everything that affects which client/creds
     * we build — not the KMS key id, which is a per-sign argument). Used to cache the KMS client.
     */
    @NotNull
    public String connectionKey() {
        String material = String.join("\n",
                region, credentialsType.name(),
                keys == null ? "" : keys.accessKeyId(),
                keys == null ? "" : keys.secret(),
                assumeRole == null ? "" : assumeRole.roleArn(),
                assumeRole == null ? "" : requireNonNullElse(assumeRole.externalId(), ""),
                requireNonNullElse(stsEndpoint, ""));
        return Sha256.hex(material.getBytes(StandardCharsets.UTF_8));
    }

    @NotNull
    @Override
    public String toString() {
        return "KmsSignerConfig{region=" + region + ", kmsKeyId=" + kmsKeyId
                + ", credentials=" + credentialsType + "}"; // keys/secret intentionally omitted
    }
}
