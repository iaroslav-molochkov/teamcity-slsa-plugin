package io.github.iaroslavmolochkov.teamcity.slsa.aws.credentials;

/** Explicit AWS access key id + secret (both required, hence non-null). */
public record AwsKeys(String accessKeyId, String secret) {
}
