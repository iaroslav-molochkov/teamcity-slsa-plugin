package io.github.iaroslavmolochkov.teamcity.slsa.aws;

import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.AssumeRoleSpec;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.AwsKeys;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.CredentialsMode;
import io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials.CredentialsSource;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SignerConfig;
import io.github.iaroslavmolochkov.teamcity.slsa.config.SlsaParams;
import io.github.iaroslavmolochkov.teamcity.slsa.provenance.Sha256;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.nio.charset.StandardCharsets;

import static java.util.Objects.requireNonNullElse;

/**
 * Validated, typed configuration for the AWS KMS signer. Required fields are non-null by construction
 * (the {@code KmsConfigMapper} guarantees it); {@code keys} is present iff the base is static and
 * {@code assumeRole} iff the mode is assume-role.
 */
public record KmsSignerConfig(
        @NotNull String region,
        @NotNull String kmsKeyId,
        @NotNull SigningAlgorithmSpec algorithm,
        @NotNull CredentialsSource source,
        @Nullable AwsKeys keys,
        @NotNull CredentialsMode mode,
        @Nullable AssumeRoleSpec assumeRole,
        @Nullable String stsEndpoint) implements SignerConfig {

    @NotNull
    @Override
    public String signerId() {
        return SlsaParams.SIGNER_AWS_KMS;
    }

    /**
     * A stable hash over the connection-relevant fields (everything that affects which client/creds
     * we build — not the KMS key id, which is a per-sign argument). Used to cache the KMS client.
     */
    @NotNull
    public String connectionKey() {
        String material = String.join("\n",
                region, source.name(), mode.name(),
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
                + ", source=" + source + ", mode=" + mode + "}"; // keys/secret intentionally omitted
    }
}
