# teamcity-slsa-plugin

A **server-side** TeamCity plugin that generates [SLSA v1.0](https://slsa.dev) provenance for a
build's artifacts and signs it as a [DSSE](https://github.com/secure-systems-lab/dsse) envelope. The
signed attestation is published back onto the build as a downloadable artifact.

Everything happens on the TeamCity **server**: artifacts are read via the server `BuildArtifacts`
API, and signing is performed server-side with a key the build agents never see. Because the
provenance is produced by the platform — not the build steps — and signed with a key the build never
sees, the build cannot forge its own attestation. That non-forgeability is the core property of SLSA
Build **L2**; full **L3** is a platform-level assessment beyond this plugin.

Signing can use **AWS KMS** (the key never leaves KMS) or a **PEM private key on the server's disk**.

## How it works

1. Add the **SLSA Provenance Attestation** build feature to a build configuration and choose a signer
   (see below).
2. When a build finishes successfully, `ProvenanceService` (driven by `ArtifactProvenanceListener`)
   orchestrates the steps below.
3. `ArtifactHasher` reads the build's file artifacts server-side (`VIEW_DEFAULT`) and SHA-256s each.
4. `ProvenanceBuilder` assembles an in-toto Statement v1 with a SLSA provenance predicate
   (build type, external/internal parameters, VCS revisions and upstream builds, builder id,
   timestamps).
5. The selected `SigningHandler` signs the DSSE PAE (`DsseService`) — for KMS via `kms:Sign`
   (`MessageType.DIGEST`), for the server key via local crypto — and wraps the result in a DSSE
   envelope.
6. `ProvenancePublisher` writes it to the build's artifacts as `provenance.sigstore.json` (a Sigstore
   bundle, for `cosign verify-blob-attestation`) and indexes its metadata.

The output format is defined by the published build-type contract,
[`docs/buildtype/v1.md`](docs/buildtype/v1.md). For step-by-step setup and verification, see
[`docs/INTEGRATION.md`](docs/INTEGRATION.md).

## Configuring the build feature

Pick a **Signer**; the form then shows only the relevant fields.

| Signer | Key location | Notes |
| --- | --- | --- |
| **AWS KMS** | AWS KMS | Sign with a KMS key. Pick a **Credentials** method below. Recommended. |
| **Server key** | PEM file on the server | Absolute path to an EC/RSA PEM (PKCS#8, PKCS#1, or SEC1). |

For the AWS KMS signer, pick a **Credentials** method (how the server authenticates to AWS):

| Credentials | Notes |
| --- | --- |
| **Default provider chain** | From the SDK default chain (env/profile/container/instance role on the server). Recommended. |
| **Static access key** | Long-lived access key id + secret (secret stored encrypted). Least preferred. |

You may additionally enable **Assume an IAM role**: the chosen base credentials are used to assume a
`kms:Sign`-scoped role via STS, and the temporary credentials perform the signing.

For AWS KMS: **KMS key id / ARN** (an asymmetric `SIGN_VERIFY` key) and **signing
algorithm** (must match the key spec, e.g. `ECDSA_SHA_256`) are required; **AWS region** is optional
— when blank, the AWS SDK resolves it from the environment (`AWS_REGION`,
profile, or instance metadata). **Fail build on error** (off by default) turns a provenance
failure from a warning into a build failure.

The feature is exported as a typed **Kotlin DSL** extension, so it can be set in a build
configuration's `features` block in `settings.kts`:

```kotlin
slsaProvenance {
    signer = kmsDefaultChain {
        region = "us-east-1"
        keyId = "arn:aws:kms:us-east-1:123456789012:key/abcd-…"
        signingAlgorithm = "ECDSA_SHA_256"
    }
    // optional: assume a kms:Sign-scoped role on top of the base credentials
    assumeRole = true
    roleArn = "arn:aws:iam::123456789012:role/tc-slsa-signer"
    // optional: fail the build instead of warning
    failBuildOnError = true
}
```

For the server-key signer, use `signer = serverKey { privateKeyPath = "/etc/teamcity/slsa/signing-key.pem" }`.
The untyped `feature { type = "slsa.provenance"; param(...) }` form also works.

### Credentials, caching, and assume-role

KMS credential resolution uses the AWS SDK's own providers. A **base** provider —
`DefaultCredentialsProvider` or `StaticCredentialsProvider` — is selected by the chosen
credentials method, and when **Assume an IAM role** is enabled it is wrapped in
`StsAssumeRoleCredentialsProvider` (which refreshes the STS session internally) layered on that base.
`KmsClientCache` caches one client per **connection**, keyed (via `AwsKmsConnectionKey`) on a hash of
the credentials method plus its identity fields (region, credentials identity, assume-role/STS
settings) — deliberately **not** on the KMS key id or the project. Builds that share a connection
reuse the client and its refreshed session credentials; evicted clients are closed.

The signing identity should be dedicated and least-privileged, and must not be shared with
credentials that are injected into build agents.

## Building

```bash
./gradlew clean test serverPlugin
```

The installable zip is written to `build/distributions/teamcity-slsa-plugin-<version>.zip` with the
AWS SDK + Jackson bundled under `server/lib` (isolated by `useSeparateClassloader`). Target a
different TeamCity API with `-Pteamcity.version=2024.12`.

## Installing

1. Build the zip.
2. In TeamCity: **Administration → Plugins → Upload plugin zip**.
3. Enable it (the descriptor allows runtime reload).
4. Add the **SLSA Provenance Attestation** feature to a build configuration and configure a signer.

After a build finishes, the signed attestation appears as the `provenance.sigstore.json` artifact,
and `SLSA:` summary lines are written to `teamcity-server.log`. To verify it — with `cosign` or
`openssl` — see [`docs/INTEGRATION.md`](docs/INTEGRATION.md) (Section 9).

> **Server URL:** the provenance records the platform identity from **Administration → Global
> Settings → Server URL**. Set it to the externally visible address so `builder.id` and
> `invocationId` are correct.

## IAM (KMS signers)

The resolved identity needs `kms:Sign` on the key. For assume-role, the base identity needs
`sts:AssumeRole` on the signing role, and the signing role holds `kms:Sign`. Verifiers fetch the
public key once via `kms:GetPublicKey` (no permission needed by the plugin itself).
