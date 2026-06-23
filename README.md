# teamcity-slsa-plugin

A **server-side** TeamCity plugin that generates [SLSA v1.0](https://slsa.dev) provenance for a
build's artifacts and **signs it with AWS KMS** as a [DSSE](https://github.com/secure-systems-lab/dsse)
envelope. The signed attestation is published back onto the build as a downloadable artifact.

Everything happens on the TeamCity **server** — artifacts are read via the server `BuildArtifacts`
API and signed with a KMS key the build agents never see. Because the provenance is produced by the
platform (not the build steps) and the signing key lives only in KMS, the attestation is
non-falsifiable by the build itself — the core property SLSA Build **L3** asks for.

## How it works

1. Add the **SLSA provenance attestation** build feature to a build configuration and point it at a
   KMS key (see below).
2. When a build finishes, `ArtifactProvenanceListener` reads its artifacts server-side and SHA-256s
   each one.
3. `ProvenanceBuilder` assembles an in-toto Statement v1 with a SLSA provenance predicate
   (build type, external/internal parameters, VCS revisions, builder id, timestamps).
4. `KmsProvenanceSigner` hashes the DSSE PAE and calls `kms:Sign` (`MessageType.DIGEST`), wrapping
   the result in a DSSE envelope.
5. `ProvenancePublisher` writes it to the build's artifacts as `slsa/provenance.intoto.jsonl`, and
   `SlsaMetadataProvider` indexes the digest for the metadata REST API.

## Configuring the build feature

| Field | Notes |
| --- | --- |
| AWS region | Region of the KMS key, e.g. `us-east-1` |
| KMS key id / ARN | An asymmetric `SIGN_VERIFY` key (id, `alias/…`, or ARN) |
| Signing algorithm | `Auto` derives it from the key, or pick `ECDSA_SHA_256`, etc. |
| Credentials | **Default provider chain** (env/profile/container/instance role on the server) or **static** access key |
| Access key id / secret | Only for static credentials; the secret is stored encrypted |
| Assume role (optional) | Role ARN + session name + external id + duration — the server assumes a `kms:Sign`-scoped role before signing |
| STS endpoint (optional) | STS endpoint override (e.g. a VPC endpoint) |

The feature is exported to the **Kotlin DSL** automatically, so it can be set in `settings.kts`:

```kotlin
feature {
    type = "slsa.provenance"
    param("slsa.aws.region", "us-east-1")
    param("slsa.kms.keyId", "arn:aws:kms:us-east-1:123456789012:key/abcd-…")
    param("slsa.aws.credentialsSource", "default")
    // optional assume-role:
    param("slsa.aws.assumeRole.arn", "arn:aws:iam::123456789012:role/tc-slsa-signer")
}
```

### Credentials, caching, and assume-role

Credential resolution uses the AWS SDK's own providers — `DefaultCredentialsProvider`,
`StaticCredentialsProvider`, or `StsAssumeRoleCredentialsProvider` (which refreshes the STS session
internally). `KmsClientCache` caches one `KmsClient` per **connection** — keyed on a hash of
region + credentials source/identity + assume-role/STS settings, deliberately **not** on the KMS key
id (a per-`sign()` argument) or the project. Builds that share a connection reuse the client (and its
refreshed session credentials); evicted clients are closed.

## Layout

| Path | Purpose |
| --- | --- |
| `feature/SlsaBuildFeature`, `SlsaParams`, `SlsaConfig` | The `slsa.provenance` build feature, its params and typed view |
| `buildServerResources/editSlsaProvenanceFeature.jsp` | The feature's settings form (TeamCity taglibs) |
| `provenance/ProvenanceBuilder`, `InTotoStatement`, `SlsaPredicate`, `Sha256` | In-toto/SLSA model + Jackson serialization |
| `signing/Pae`, `DsseEnvelope`, `KmsProvenanceSigner` | DSSE encoding and KMS signing |
| `aws/AwsCredentialsResolver`, `KmsClientFactory`, `KmsClientCache` | AWS SDK plumbing |
| `persist/ProvenancePublisher`, `SlsaMetadataProvider` | Publishes the artifact and indexes metadata |
| `ArtifactProvenanceListener` | Orchestrates build → sign → publish on `buildFinished` |

Spring wiring is annotation-driven (`@Component` + `<context:component-scan>` in
`META-INF/build-server-plugin-teamcity-slsa.xml`).

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
4. Add the **SLSA provenance attestation** feature to a build configuration and configure KMS.

After a build finishes, the signed attestation appears as the `slsa/provenance.intoto.jsonl`
artifact, and `SLSA:` summary lines are written to `teamcity-server.log`. Verify the envelope with
the KMS key's public key (e.g. via `cosign`/`dsse` tooling or `kms:GetPublicKey`).

## IAM

The resolved identity needs `kms:Sign` on the key (and `kms:DescribeKey` when the signing algorithm
is left on `Auto`). For assume-role, the base identity needs `sts:AssumeRole` on the signing role,
and the signing role holds the `kms:Sign` permission.
